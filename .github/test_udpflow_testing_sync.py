import base64
import contextlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import udpflow_testing_sync as sync
import udpflow_testing_release as release


def published(version, **values):
    return {"tag_name": "v" + version, "draft": False, "prerelease": True, "published_at": "2026-09-20T01:00:00Z", **values}


def release_page(nodes, cursor=None):
    return {"data": {"repository": {"releases": {"nodes": nodes, "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor}}}}}


class SourceSelectionTest(unittest.TestCase):
    def setUp(self):
        self.source = {"upstream_branch": "testing", "upstream_version": "1.15.0-alpha.6", "upstream_commit": "a" * 40, "android_client_commit": "b" * 40, "fork_revision": 2}

    def test_semantic_release_order_and_pagination_exclude_drafts_and_stable(self):
        page = [published("1.15.0-alpha.9")] * 97 + [published("1.15.0-alpha.10"), published("9.0.0", prerelease=False), published("9.0.0-rc.1", draft=True)]
        last = [published("1.15.0-beta.2"), published("1.15.0-rc.1"), published("1.15.0-rc.2", published_at=None)]
        with patch.object(sync, "api", side_effect=[release_page(page, "next-page"), release_page(last)]) as api:
            self.assertEqual(sync.latest_testing_release(), published("1.15.0-rc.1"))
        self.assertEqual(api.call_args.args, ("graphql",))
        self.assertEqual(api.call_args.kwargs["data"]["variables"]["cursor"], "next-page")
        self.assertIsNone(api.call_args_list[0].kwargs["data"]["variables"]["cursor"])
        self.assertNotIn("assets", api.call_args.kwargs["data"]["query"])
        for invalid in ("1.15.0", "1.15.0-alpha.06", "01.15.0-alpha.6", "v1.15.0-alpha.6", "1.15.0-alpha.6-udpflow.2"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                sync.version_key(invalid)

    def test_no_published_testing_release_is_a_visible_failure(self):
        with patch.object(sync, "api", return_value=release_page([published("1.15.0", prerelease=False)])):
            with self.assertRaisesRegex(ValueError, "No published"):
                sync.latest_testing_release()

    def test_partial_graphql_errors_and_missing_repository_fail_visibly(self):
        partial = release_page([published("1.15.0-alpha.7")])
        partial["errors"] = [{"message": "query failed"}]
        for response in (partial, {"data": {"repository": None}}):
            with self.subTest(response=response), patch.object(sync, "api", return_value=response):
                with self.assertRaisesRegex(ValueError, "GitHub release query"):
                    sync.latest_testing_release()

    def test_stuck_pagination_does_not_return_an_incomplete_release_list(self):
        page = release_page([published("1.15.0-alpha.7")], "same-cursor")
        with patch.object(sync, "api", return_value=page) as api:
            with self.assertRaisesRegex(ValueError, "pagination did not advance"):
                sync.latest_testing_release()
        self.assertEqual(api.call_count, 2)

    def test_current_release_keeps_client_pin_and_fork_revision(self):
        with patch.object(sync, "latest_testing_release", return_value=published("1.15.0-alpha.6")), patch.object(sync, "tag_commit", return_value="a" * 40), patch.object(sync, "matching_android_commit") as android:
            self.assertEqual(sync.select_source(self.source), self.source)
            android.assert_not_called()

    def test_new_release_pins_matching_client_and_resets_revision(self):
        expected = {**self.source, "upstream_version": "1.15.0-alpha.7", "upstream_commit": "c" * 40, "android_client_commit": "d" * 40, "fork_revision": 1}
        with patch.object(sync, "latest_testing_release", return_value=published("1.15.0-alpha.7")), patch.object(sync, "tag_commit", return_value="c" * 40), patch.object(sync, "matching_android_commit", return_value="d" * 40) as android:
            self.assertEqual(sync.select_source(self.source), expected)
            android.assert_called_once_with("1.15.0-alpha.7")

    def test_moved_tag_and_downgrade_fail_before_build(self):
        for version, commit, message in (("1.15.0-alpha.6", "c" * 40, "moved"), ("1.15.0-alpha.5", "a" * 40, "downgrade")):
            with self.subTest(version=version), patch.object(sync, "latest_testing_release", return_value=published(version)), patch.object(sync, "tag_commit", return_value=commit):
                with self.assertRaisesRegex(ValueError, message):
                    sync.select_source(self.source)

    def test_annotated_release_tags_are_resolved(self):
        with patch.object(sync, "api", side_effect=[{"object": {"type": "tag", "sha": "b" * 40}}, {"object": {"type": "commit", "sha": "a" * 40}}]):
            self.assertEqual(sync.tag_commit("v1.15.0-alpha.6"), "a" * 40)

    def test_android_version_search_is_pinned_to_observed_head(self):
        with patch.object(sync, "api", side_effect=[{"sha": "c" * 40}, [{"sha": "c" * 40}, {"sha": "d" * 40}]]) as api, patch.object(sync, "android_properties", side_effect=[{"VERSION_NAME": "1.15.0-alpha.8"}, {"VERSION_NAME": "1.15.0-alpha.7"}]):
            self.assertEqual(sync.matching_android_commit("1.15.0-alpha.7"), "d" * 40)
            self.assertIn("sha=" + "c" * 40, api.call_args.args[0])
        with patch.object(sync, "api", side_effect=[{"sha": "c" * 40}, []]), patch.object(sync, "android_properties", return_value={"VERSION_NAME": "1.15.0-alpha.8"}):
            with self.assertRaisesRegex(ValueError, "no matching"):
                sync.matching_android_commit("1.15.0-alpha.7")

    def test_android_properties_decode_and_match_version(self):
        content = base64.b64encode(b"VERSION_NAME=1.15.0-alpha.7\nGO_VERSION=go1.26.8\n").decode()
        with patch.object(sync, "api", return_value={"content": content}):
            self.assertEqual(sync.android_properties("a" * 40), {"VERSION_NAME": "1.15.0-alpha.7", "GO_VERSION": "go1.26.8"})

    def test_scheduled_or_manual_published_release_skips_build_unless_forced(self):
        for event, force, build in (("schedule", "false", "false"), ("workflow_dispatch", "false", "false"), ("workflow_dispatch", "true", "true")):
            with self.subTest(event=event, force=force), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                with patch.object(release, "snapshot", return_value=(self.source, "unused")), patch.object(sync, "select_source", return_value=self.source), patch.object(release, "api", return_value={"draft": False, "prerelease": True}), patch.dict(os.environ, GITHUB_EVENT_NAME=event, GITHUB_REF="refs/heads/udpflow-testing", GITHUB_REPOSITORY="example/fork", GITHUB_OUTPUT=str(output), SYNC_UPSTREAM="true", FORCE_BUILD=force):
                    release.plan()
                values = release.properties(output)
                self.assertEqual(values["build"], build)
                self.assertEqual(values["publish"], "false")
                self.assertEqual(json.loads(values["source"]), self.source)
                self.assertEqual(values["reason"], "verify-current-source" if force == "true" else "already-published")

    def test_new_or_unpublished_revision_builds_and_draft_can_resume(self):
        for new_upstream, prior in ((False, None), (False, {"draft": True}), (True, None)):
            with self.subTest(new_upstream=new_upstream, prior=prior), tempfile.TemporaryDirectory() as directory:
                source = {**self.source, "upstream_version": "1.15.0-alpha.7", "fork_revision": 1} if new_upstream else self.source
                output = Path(directory) / "output"
                with patch.object(release, "snapshot", return_value=(self.source, "unused")), patch.object(sync, "select_source", return_value=source), patch.object(release, "api", return_value=prior), patch.dict(os.environ, GITHUB_EVENT_NAME="schedule", GITHUB_REF="refs/heads/udpflow-testing", GITHUB_REPOSITORY="example/fork", GITHUB_OUTPUT=str(output)):
                    release.plan()
                values = release.properties(output)
                self.assertEqual((values["build"], values["publish"]), ("true", "true"))
                self.assertEqual(values["reason"], "new-upstream-release" if new_upstream else "unpublished-fork-revision")

    def test_public_new_release_with_stale_manifest_requires_reconciliation(self):
        with patch.object(release, "snapshot", return_value=(self.source, "unused")), patch.object(sync, "select_source", return_value={**self.source, "upstream_version": "1.15.0-alpha.7"}), patch.object(release, "api", return_value={"draft": False, "prerelease": True}), patch.dict(os.environ, GITHUB_EVENT_NAME="schedule", GITHUB_REF="refs/heads/udpflow-testing", GITHUB_REPOSITORY="example/fork"):
            with self.assertRaisesRegex(ValueError, "reconcile"):
                release.plan()


class SnapshotMergeTest(unittest.TestCase):
    """Use real local Git repositories, module migrations and client submodules."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = patch.dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.com", GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.com", GIT_ALLOW_PROTOCOL="file", GITHUB_RUN_NUMBER="71", GITHUB_OUTPUT=str(self.root / "output"), RUNNER_TEMP=str(self.root), PUBLISH_RELEASE="true")
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.module = self.root / "module"
        self.core = self.root / "core"
        self.client = self.root / "client"
        for directory in (self.module, self.core, self.client):
            self.git("init", "-b", "main", str(directory))
        (self.module / "upstream.go").write_text("upstream old\n")
        (self.module / "patched.go").write_text("base\n")
        (self.module / "obsolete.go").write_text("old\n")
        self.old_module = self.commit(self.module, "module old")
        self.git("tag", "v0.1.0", cwd=self.module)
        (self.module / "upstream.go").write_text("upstream new\n")
        (self.module / "obsolete.go").unlink()
        self.new_module = self.commit(self.module, "module new")
        self.git("tag", "v0.2.0", cwd=self.module)
        (self.client / "version.properties").write_text("VERSION_NAME=1.15.0-alpha.6\nVERSION_CODE=40\nGO_VERSION=go1.26.8\n")
        (self.client / "update-url").write_text("official\n")
        old_client = self.commit(self.client, "old Android")
        (self.core / ".github").mkdir()
        (self.core / ".github/owned").write_text("official\n")
        (self.core / "core.go").write_text("old core\n")
        (self.core / "fork-patched.go").write_text("original\n")
        (self.core / "test").mkdir()
        for file in ("go.mod", "test/go.mod"):
            (self.core / file).write_text("require github.com/sagernet/sing-mux v0.1.0\n")
        self.git("submodule", "add", str(self.client), "clients/android", cwd=self.core)
        old_core = self.commit(self.core, "old core")
        self.git("tag", "v1.15.0-alpha.6", cwd=self.core)
        self.fork = self.root / "fork"
        self.git("clone", str(self.core), str(self.fork))
        (self.fork / ".github/owned").write_text("fork automation\n")
        (self.fork / "fork-patched.go").write_text("fork fix\n")
        (self.fork / "release").mkdir()
        self.current = {"upstream_branch": "testing", "upstream_version": "1.15.0-alpha.6", "upstream_commit": old_core, "android_client_commit": old_client, "fork_revision": 2}
        (self.fork / "release/udpflow.json").write_text(json.dumps(self.current))
        (self.fork / ".github/android-udpflow.patch").write_text("diff --git a/update-url b/update-url\n--- a/update-url\n+++ b/update-url\n@@ -1 +1 @@\n-official\n+fork\n")
        vendor = self.fork / "third_party/sing-mux"
        vendor.mkdir(parents=True)
        (vendor / "upstream.go").write_text("upstream old\n")
        (vendor / "patched.go").write_text("fork module fix\n")
        (vendor / "obsolete.go").write_text("old\n")
        (vendor / "UPSTREAM_VERSION").write_text("v0.1.0\n")
        self.base = self.commit(self.fork, "fork fixes")
        (self.client / "version.properties").write_text("VERSION_NAME=1.15.0-alpha.7\nVERSION_CODE=41\nGO_VERSION=go1.26.8\n")
        self.new_client = self.commit(self.client, "new Android")
        (self.core / "core.go").write_text("new core\n")
        (self.core / ".github/owned").write_text("new official automation\n")
        for file in ("go.mod", "test/go.mod"):
            (self.core / file).write_text("require github.com/sagernet/sing-mux v0.2.0\n")
        self.new_core = self.commit(self.core, "new core")
        self.git("tag", "v1.15.0-alpha.7", cwd=self.core)
        self.selected = {**self.current, "upstream_version": "1.15.0-alpha.7", "upstream_commit": self.new_core, "android_client_commit": self.new_client, "fork_revision": 1}

    def git(self, *args, cwd=None, **kwargs):
        return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.DEVNULL, **kwargs).strip()

    def commit(self, directory, message):
        self.git("add", ".", cwd=directory)
        self.git("commit", "-m", message, cwd=directory)
        return self.git("rev-parse", "HEAD", cwd=directory)

    def prepare(self):
        original = sync.git

        def local_git(*args, **kwargs):
            replacements = {f"https://github.com/{sync.UPSTREAM}.git": str(self.core), "https://github.com/SagerNet/sing-mux.git": str(self.module)}
            return original(*(replacements.get(str(arg), arg) for arg in args), **kwargs)

        with contextlib.chdir(self.fork), patch.object(sync, "git", side_effect=local_git), patch.object(release, "git", side_effect=local_git), patch.object(sync, "MODULES", ("sing-mux",)), patch.dict(os.environ, TESTING_SOURCE=json.dumps(self.selected)):
            release.prepare()

    def test_new_release_preserves_fork_and_rebases_real_module_before_publication(self):
        self.prepare()
        self.assertEqual((self.fork / "core.go").read_text(), "new core\n")
        self.assertEqual((self.fork / "fork-patched.go").read_text(), "fork fix\n")
        self.assertEqual((self.fork / ".github/owned").read_text(), "fork automation\n")
        vendor = self.fork / "third_party/sing-mux"
        self.assertEqual((vendor / "upstream.go").read_text(), "upstream new\n")
        self.assertEqual((vendor / "patched.go").read_text(), "fork module fix\n")
        self.assertEqual((vendor / "UPSTREAM_VERSION").read_text(), "v0.2.0\n")
        self.assertFalse((vendor / "obsolete.go").exists())
        self.assertEqual((self.fork / "clients/android/update-url").read_text(), "fork\n")
        self.assertEqual(json.loads((self.fork / "release/udpflow.json").read_text()), self.selected)
        state = json.loads((self.root / "udpflow-source.json").read_text())
        self.assertEqual(state["base"], self.base)
        self.assertEqual(state["commit"], self.git("rev-parse", "HEAD", cwd=self.fork))
        self.assertEqual(state["tag"], "v1.15.0-alpha.7-udpflow.1")
        self.assertEqual(self.git("rev-parse", state["tag"], cwd=self.fork), state["commit"])
        self.assertEqual(release.properties(self.fork / "clients/android/version.properties")["VERSION_CODE"], "1000071")
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.core), self.new_core)
        self.assertNotIn("udpflow", self.git("tag", cwd=self.core))

    def test_pseudo_versions_resolve_to_full_commits_before_git_fetch(self):
        previous = "v0.1.1-0.20260918010000-" + self.old_module[:12]
        required = "v0.2.1-0.20260920010000-" + self.new_module[:12]
        directory = self.fork / "third_party/sing-mux"
        (directory / "UPSTREAM_VERSION").write_text(previous + "\n")
        original = sync.git

        def local_git(*args, **kwargs):
            return original(*(str(self.module) if arg == "https://github.com/SagerNet/sing-mux.git" else arg for arg in args), **kwargs)

        with patch.object(sync, "git", side_effect=local_git), patch.object(sync, "api", side_effect=[{"sha": self.old_module}, {"sha": self.new_module}]):
            sync.migrate_module("sing-mux", directory, required)
        self.assertEqual((directory / "UPSTREAM_VERSION").read_text(), required + "\n")
        self.assertEqual((directory / "patched.go").read_text(), "fork module fix\n")
        self.assertEqual((directory / "upstream.go").read_text(), "upstream new\n")

    def test_publish_advances_only_the_tested_base_and_never_overwrites_public_release(self):
        self.prepare()
        state = json.loads((self.root / "udpflow-source.json").read_text())
        distribution = self.fork / "dist/android"
        distribution.mkdir(parents=True)
        metadata = {"core_commit": state["commit"], "version_name": state["version"], "upstream_commit": state["upstream_commit"], "android_client_commit": state["android_client_commit"]}
        (distribution / "SFA-version-metadata.json").write_text(json.dumps(metadata))
        for remote, public, error in ((self.base, False, None), (state["commit"], False, None), ("f" * 40, False, "changed during"), (self.base, True, "cannot be overwritten")):
            with self.subTest(remote=remote, public=public):
                commands = []

                def publisher_git(*args):
                    commands.append(args)
                    if args[0] == "ls-remote":
                        return remote + "\trefs/heads/udpflow-testing"
                    return ""

                with contextlib.chdir(self.fork), patch.dict(os.environ, GITHUB_REF="refs/heads/udpflow-testing", GITHUB_REPOSITORY="example/fork"), patch.object(release, "api", return_value={"draft": False} if public else None), patch.object(release, "git", side_effect=publisher_git), patch.object(release.subprocess, "run") as gh:
                    if error:
                        with self.assertRaisesRegex(ValueError, error):
                            release.publish()
                        gh.assert_not_called()
                        self.assertFalse(any(c[0] == "push" for c in commands))
                    else:
                        release.publish()
                        self.assertIn(("push", "--atomic", "origin", state["commit"] + ":refs/heads/udpflow-testing", state["commit"] + ":refs/tags/" + state["tag"]), commands)
                        self.assertEqual(gh.call_count, 2)

    def test_rewritten_upstream_history_uses_recorded_snapshot_base(self):
        # Same new tree on a disconnected history, like upstream testing rebases.
        tree = self.git("rev-parse", "HEAD^{tree}", cwd=self.core)
        unrelated = self.git("commit-tree", tree, "-m", "rewritten upstream", cwd=self.core)
        self.git("tag", "-f", "v1.15.0-alpha.7", unrelated, cwd=self.core)
        self.selected["upstream_commit"] = unrelated
        self.prepare()
        self.assertEqual((self.fork / "fork-patched.go").read_text(), "fork fix\n")
        self.git("merge-base", "--is-ancestor", unrelated, "HEAD", cwd=self.fork)

    def test_core_conflict_does_not_move_fork_head_or_change_manifest(self):
        (self.core / "fork-patched.go").write_text("incompatible upstream fix\n")
        self.selected["upstream_commit"] = self.commit(self.core, "conflict")
        self.git("tag", "-f", "v1.15.0-alpha.7", self.selected["upstream_commit"], cwd=self.core)
        with self.assertRaisesRegex(ValueError, "patch conflict"):
            self.prepare()
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.fork), self.base)
        self.assertEqual(json.loads((self.fork / "release/udpflow.json").read_text()), self.current)
        self.assertFalse((self.root / "udpflow-source.json").exists())

    def test_vendor_conflict_retains_previous_vendor_and_never_prepares_release(self):
        (self.module / "patched.go").write_text("incompatible upstream module fix\n")
        commit = self.commit(self.module, "conflict")
        self.git("tag", "-f", "v0.2.0", commit, cwd=self.module)
        with self.assertRaisesRegex(ValueError, "sing-mux.*patch conflict"):
            self.prepare()
        vendor = self.fork / "third_party/sing-mux"
        self.assertEqual((vendor / "UPSTREAM_VERSION").read_text(), "v0.1.0\n")
        self.assertEqual((vendor / "patched.go").read_text(), "fork module fix\n")
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.fork), self.base)
        self.assertFalse((self.root / "udpflow-source.json").exists())

    def test_moved_release_tag_is_rejected_before_source_merge(self):
        self.git("tag", "-f", "v1.15.0-alpha.7", self.current["upstream_commit"], cwd=self.core)
        with self.assertRaisesRegex(ValueError, "tag changed"):
            self.prepare()
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.fork), self.base)

    def test_unchanged_upstream_test_pin_follows_core_and_preserves_module_format(self):
        test_module = self.fork / "test/go.mod"
        content = "module example/test\n\nrequire (\n\tgithub.com/sagernet/sing-mux v0.1.0 // indirect\n)\n\nreplace github.com/sagernet/sing-mux => ../third_party/sing-mux\n"
        test_module.write_text(content)
        self.base = self.commit(self.fork, "local test module replacement")
        (self.core / "test/go.mod").write_text("require github.com/sagernet/sing-mux v0.1.0\n")
        self.selected["upstream_commit"] = self.commit(self.core, "keep previous test dependency")
        self.git("tag", "-f", "v1.15.0-alpha.7", self.selected["upstream_commit"], cwd=self.core)
        self.prepare()
        self.assertEqual(test_module.read_text(), content.replace("v0.1.0", "v0.2.0"))
        self.assertEqual(self.git("show", "HEAD:test/go.mod", cwd=self.fork), test_module.read_text().strip())
        self.assertEqual((self.fork / "third_party/sing-mux/UPSTREAM_VERSION").read_text(), "v0.2.0\n")
        self.assertEqual((self.fork / "third_party/sing-mux/patched.go").read_text(), "fork module fix\n")
        self.assertEqual((self.fork / "third_party/sing-mux/upstream.go").read_text(), "upstream new\n")

    def test_test_pin_already_corrected_in_fork_follows_next_core_bump(self):
        # Reproduce alpha.8: upstream test/go.mod is older than both the fork's
        # last reviewed core and its test pin, and remains unchanged upstream.
        self.git("checkout", "--detach", self.current["upstream_commit"], cwd=self.core)
        (self.core / "test/go.mod").write_text("require github.com/sagernet/sing-mux v0.0.5\n")
        self.current["upstream_commit"] = self.commit(self.core, "old upstream test pin")
        self.git("fetch", str(self.core), self.current["upstream_commit"], cwd=self.fork)
        (self.fork / "release/udpflow.json").write_text(json.dumps(self.current))
        fork_commit = self.commit(self.fork, "record old upstream snapshot")
        tree = self.git("rev-parse", "HEAD^{tree}", cwd=self.fork)
        self.base = self.git("commit-tree", tree, "-p", fork_commit, "-p", self.current["upstream_commit"], "-m", "retain upstream ancestry", cwd=self.fork)
        self.git("update-ref", "HEAD", self.base, fork_commit, cwd=self.fork)
        self.git("checkout", "--detach", self.new_core, cwd=self.core)
        (self.core / "test/go.mod").write_text("require github.com/sagernet/sing-mux v0.0.5\n")
        self.selected["upstream_commit"] = self.commit(self.core, "keep older upstream test pin")
        self.git("tag", "-f", "v1.15.0-alpha.7", self.selected["upstream_commit"], cwd=self.core)
        self.prepare()
        for path in ("go.mod", "test/go.mod"):
            self.assertEqual(sync.module_requirement(self.fork / path, "sing-mux"), "v0.2.0")
            self.assertIn("v0.2.0", self.git("show", f"HEAD:{path}", cwd=self.fork))
        self.assertEqual((self.fork / "third_party/sing-mux/UPSTREAM_VERSION").read_text(), "v0.2.0\n")

    def test_changed_mismatched_upstream_test_dependency_blocks_migration(self):
        (self.core / "test/go.mod").write_text("require github.com/sagernet/sing-mux v0.3.0\n")
        self.selected["upstream_commit"] = self.commit(self.core, "mismatched requirements")
        self.git("tag", "-f", "v1.15.0-alpha.7", self.selected["upstream_commit"], cwd=self.core)
        with self.assertRaisesRegex(ValueError, "disagree"):
            self.prepare()
        self.assertFalse((self.root / "udpflow-source.json").exists())
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.fork), self.base)
        self.assertEqual((self.fork / "third_party/sing-mux/UPSTREAM_VERSION").read_text(), "v0.1.0\n")

    def test_inconsistent_current_test_module_blocks_migration(self):
        (self.fork / "test/go.mod").write_text("require github.com/sagernet/sing-mux v0.0.9\n")
        self.base = self.commit(self.fork, "unreviewed test dependency")
        with self.assertRaisesRegex(ValueError, "Current core, test module and local patches disagree"):
            self.prepare()
        self.assertFalse((self.root / "udpflow-source.json").exists())
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.fork), self.base)

    def test_inconsistent_current_vendor_blocks_migration(self):
        (self.fork / "third_party/sing-mux/UPSTREAM_VERSION").write_text("v0.0.9\n")
        self.base = self.commit(self.fork, "unreviewed vendor version")
        with self.assertRaisesRegex(ValueError, "Current core, test module and local patches disagree"):
            self.prepare()
        self.assertFalse((self.root / "udpflow-source.json").exists())
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.fork), self.base)

    def test_nonmatching_client_version_blocks_release(self):
        (self.client / "version.properties").write_text("VERSION_NAME=1.15.0-alpha.8\n")
        self.selected["android_client_commit"] = self.commit(self.client, "wrong version")
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.prepare()
        self.assertFalse((self.root / "udpflow-source.json").exists())


if __name__ == "__main__":
    unittest.main()
