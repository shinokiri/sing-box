import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("udpflow_release", Path(__file__).with_name("udpflow_release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTest(unittest.TestCase):
    def test_fork_versions_keep_official_version_and_allow_numeric_revisions(self):
        self.assertEqual(release.fork_version("v1.14.0"), "1.14.0-udpflow")
        self.assertEqual(release.fork_version("v1.14.0", 1), "1.14.0-udpflow.1")
        self.assertEqual(release.fork_version("v1.14.0", 10), "1.14.0-udpflow.10")
        for revision in (-1, "1", 1.5, True):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                release.fork_version("v1.14.0", revision)

    def test_revision_selection_and_upstream_revision_reset(self):
        for tag, published, expected_tag, build in (
            ("v1.14.0", False, "v1.14.0-udpflow.2", "true"),
            ("v1.14.0", True, "v1.14.0-udpflow.2", "false"),
            ("v1.14.1", False, "v1.14.1-udpflow", "true"),
        ):
            with self.subTest(tag=tag, published=published), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                current = {"upstream_tag": "v1.14.0", "upstream_commit": "a" * 40, "fork_revision": 2}
                responses = [
                    {"tag_name": tag, "draft": False, "prerelease": False},
                    {"object": {"type": "commit", "sha": current["upstream_commit"]}},
                    {"draft": False, "prerelease": False} if published else None,
                ]
                with patch.object(release.MANIFEST.__class__, "read_text", return_value=json.dumps(current)), patch.object(release, "api", side_effect=responses) as api, patch.dict(os.environ, GITHUB_EVENT_NAME="schedule", GITHUB_REPOSITORY="example/fork", GITHUB_OUTPUT=str(output), SYNC_UPSTREAM="true"):
                    release.plan()
                api.assert_any_call(f"repos/example/fork/releases/tags/{expected_tag}", missing_ok=True)
                values = release.properties(output)
                self.assertEqual(values["build"], build)
                self.assertEqual(values["publish"], str(not published).lower())

    def test_only_canonical_stable_versions(self):
        self.assertEqual(release.stable_version("v1.14.0"), (1, 14, 0))
        for tag in ("vv1.14.0", "v1.14.0-rc.1", "v1.14.0-udpflow", "v01.14.0", "1.14.0"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.stable_version(tag)

    def test_published_release_skips_scheduled_build_but_keeps_push_artifacts(self):
        for event, build in (("schedule", "false"), ("push", "true")):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                current = {"upstream_tag": "v1.14.0", "upstream_commit": "a" * 40}
                responses = [
                    {"tag_name": "v1.14.0", "draft": False, "prerelease": False},
                    {"object": {"type": "commit", "sha": current["upstream_commit"]}},
                    {"draft": False, "prerelease": False},
                ]
                with patch.object(release.MANIFEST.__class__, "read_text", return_value=json.dumps(current)), patch.object(release, "api", side_effect=responses), patch.dict(os.environ, GITHUB_EVENT_NAME=event, GITHUB_REPOSITORY="example/fork", GITHUB_OUTPUT=str(output)):
                    release.plan()
                values = release.properties(output)
                self.assertEqual(values["build"], build)
                self.assertEqual(values["publish"], "false")

    def test_moved_current_tag_is_detected_before_skipping_published_release(self):
        current = {"upstream_tag": "v1.14.0", "upstream_commit": "a" * 40}
        responses = [
            {"tag_name": "v1.14.0", "draft": False, "prerelease": False},
            {"object": {"type": "commit", "sha": "b" * 40}},
            {"draft": False, "prerelease": False},
        ]
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(release.MANIFEST.__class__, "read_text", return_value=json.dumps(current)), patch.object(release, "api", side_effect=responses), patch.dict(os.environ, GITHUB_EVENT_NAME="schedule", GITHUB_REPOSITORY="example/fork", GITHUB_OUTPUT=str(Path(directory) / "output")):
                with self.assertRaisesRegex(ValueError, "Recorded upstream tag was moved"):
                    release.plan()


class FollowUpstreamTest(unittest.TestCase):
    """Exercise actual Git merges, client pins and tags without network/pushes."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.upstream = root / "upstream"
        self.client = root / "client"
        self.fork = root / "fork"
        self.env = patch.dict(os.environ, {
            "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
            "GIT_ALLOW_PROTOCOL": "file", "GITHUB_RUN_NUMBER": "61",
            "GITHUB_OUTPUT": str(root / "output"), "RUNNER_TEMP": str(root),
            "UPSTREAM_TAG": "v1.14.1", "PUBLISH_RELEASE": "true",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        for repo in (self.upstream, self.client):
            repo.mkdir()
            self.git(repo, "init", "-b", "main")
        (self.client / "version.properties").write_text("VERSION_NAME=1.14.0\nVERSION_CODE=730\nGO_VERSION=go1.26.7\n")
        (self.client / "update-url").write_text("official\n")
        self.commit(self.client, "client 1.14.0")
        (self.upstream / ".github/workflows").mkdir(parents=True)
        (self.upstream / ".github/workflows/build.yml").write_text("official workflow\n")
        (self.upstream / "core.go").write_text("original core\n")
        (self.upstream / "obsolete.txt").write_text("removed in the next upstream version\n")
        (self.upstream / "rename.txt").write_text("".join(f"line {i}\n" for i in range(20)))
        self.git(self.upstream, "submodule", "add", str(self.client), "clients/android")
        base = self.commit(self.upstream, "core 1.14.0")
        self.git(self.upstream, "tag", "v1.14.0")
        self.git(root, "clone", str(self.upstream), str(self.fork))
        (self.fork / ".github/workflows/build.yml").write_text("udpflow workflow\n")
        (self.fork / "udpflow.go").write_text("fork feature\n")
        (self.fork / "release").mkdir()
        (self.fork / "release/udpflow.json").write_text(json.dumps({"upstream_tag": "v1.14.0", "upstream_commit": base}))
        (self.fork / ".github/android-udpflow.patch").write_text("diff --git a/update-url b/update-url\n--- a/update-url\n+++ b/update-url\n@@ -1 +1 @@\n-official\n+fork\n")
        self.commit(self.fork, "udpflow customization")
        (self.client / "version.properties").write_text("VERSION_NAME=1.14.1\nVERSION_CODE=731\nGO_VERSION=go1.26.7\n")
        self.client_commit = self.commit(self.client, "client 1.14.1")
        (self.upstream / "core.go").write_text("new upstream core\n")
        (self.upstream / "obsolete.txt").unlink()
        (self.upstream / ".github/workflows/build.yml").write_text("new official workflow\n")
        self.target = self.commit(self.upstream, "core 1.14.1")
        self.git(self.upstream, "tag", "v1.14.1")
        os.environ["UPSTREAM_COMMIT"] = self.target

    def git(self, cwd, *args):
        return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.DEVNULL).strip()

    def commit(self, repo, message):
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-m", message)
        return self.git(repo, "rev-parse", "HEAD")

    def prepare(self):
        original = release.git

        def local_git(*args, **kwargs):
            args = [str(self.upstream) if arg == f"https://github.com/{release.UPSTREAM}.git" else arg for arg in args]
            return original(*args, **kwargs)

        with contextlib.chdir(self.fork), patch.object(release, "git", side_effect=local_git):
            release.prepare()

    def test_merge_keeps_fork_workflow_and_uses_matching_client(self):
        self.prepare()
        self.git(self.fork, "merge-base", "--is-ancestor", self.target, "HEAD")
        self.assertEqual((self.fork / "udpflow.go").read_text(), "fork feature\n")
        self.assertEqual((self.fork / ".github/workflows/build.yml").read_text(), "udpflow workflow\n")
        self.assertEqual((self.fork / "core.go").read_text(), "new upstream core\n")
        client = self.fork / "clients/android"
        self.assertEqual(self.git(client, "rev-parse", "HEAD"), self.client_commit)
        self.assertEqual((client / "update-url").read_text(), "fork\n")
        props = release.properties(client / "version.properties")
        self.assertEqual(props["VERSION_NAME"], "1.14.1-udpflow")
        self.assertEqual(props["VERSION_CODE"], "1000061")
        self.assertEqual(self.git(self.fork, "describe", "--tags", "--exact-match"), "v1.14.1-udpflow")
        # Preparing/testing never publishes a branch or release.
        self.assertEqual(self.git(self.upstream, "rev-parse", "HEAD"), self.target)

    def test_fork_revision_builds_existing_base_without_replacing_public_tag(self):
        manifest = self.fork / "release/udpflow.json"
        current = json.loads(manifest.read_text())
        previous = self.git(self.fork, "rev-parse", "HEAD")
        self.git(self.fork, "tag", "v1.14.0-udpflow", previous)
        current["fork_revision"] = 1
        manifest.write_text(json.dumps(current))
        before = self.commit(self.fork, "release fork revision 1")
        os.environ.update(UPSTREAM_TAG=current["upstream_tag"], UPSTREAM_COMMIT=current["upstream_commit"], GITHUB_RUN_NUMBER="67")
        self.prepare()
        self.assertEqual(self.git(self.fork, "rev-parse", "HEAD"), before)
        self.assertEqual(self.git(self.fork, "rev-parse", "v1.14.0-udpflow"), previous)
        self.assertEqual(self.git(self.fork, "rev-parse", "v1.14.0-udpflow.1"), before)
        props = release.properties(self.fork / "clients/android/version.properties")
        self.assertEqual(props["VERSION_NAME"], "1.14.0-udpflow.1")
        self.assertEqual(props["VERSION_CODE"], "1000067")
        state = json.loads((Path(self.temp.name) / "udpflow-source.json").read_text())
        self.assertEqual(state["commit"], before)
        self.assertEqual(state["tag"], "v1.14.0-udpflow.1")

    def test_snapshot_after_revision_has_a_distinct_version_and_tag(self):
        manifest = self.fork / "release/udpflow.json"
        current = json.loads(manifest.read_text())
        current["fork_revision"] = 1
        manifest.write_text(json.dumps(current))
        self.commit(self.fork, "release fork revision 1")
        self.git(self.fork, "tag", "v1.14.0-udpflow.1")
        (self.fork / "udpflow.go").write_text("next fork change\n")
        before = self.commit(self.fork, "next change")
        os.environ.update(UPSTREAM_TAG=current["upstream_tag"], UPSTREAM_COMMIT=current["upstream_commit"], PUBLISH_RELEASE="false")
        self.prepare()
        version = f"1.14.0-udpflow.1.g{before[:7]}"
        self.assertEqual(release.properties(self.fork / "clients/android/version.properties")["VERSION_NAME"], version)
        self.assertEqual(self.git(self.fork, "rev-parse", f"v{version}"), before)

    def test_following_upstream_resets_recorded_fork_revision(self):
        manifest = self.fork / "release/udpflow.json"
        current = json.loads(manifest.read_text())
        current["fork_revision"] = 3
        manifest.write_text(json.dumps(current))
        self.commit(self.fork, "third revision on previous official release")
        self.prepare()
        self.assertEqual(json.loads(manifest.read_text())["fork_revision"], 0)
        self.assertEqual(release.properties(self.fork / "clients/android/version.properties")["VERSION_NAME"], "1.14.1-udpflow")

    def test_core_conflict_stops_before_commit_or_release(self):
        (self.fork / "core.go").write_text("fork changed the same line\n")
        before = self.commit(self.fork, "fork core change")
        with self.assertRaisesRegex(ValueError, "merge needs review"):
            self.prepare()
        self.assertEqual(self.git(self.fork, "rev-parse", "HEAD"), before)
        self.assertFalse((Path(self.temp.name) / "udpflow-source.json").exists())

    def test_mismatched_client_stops_before_commit_or_release(self):
        (self.client / "version.properties").write_text("VERSION_NAME=1.15.0-beta.1\nVERSION_CODE=732\nGO_VERSION=go1.26.7\n")
        self.commit(self.client, "client is on a different track")
        before = self.git(self.fork, "rev-parse", "HEAD")
        with self.assertRaisesRegex(ValueError, "Android main has not reached"):
            self.prepare()
        self.assertEqual(self.git(self.fork, "rev-parse", "HEAD"), before)

    def rewrite_upstream_history(self):
        # Rebuild the old release with the same files but different history,
        # then publish the next release on that rewritten line of development.
        old = self.git(self.upstream, "rev-parse", "v1.14.0")
        rewritten_base = self.git(self.upstream, "commit-tree", f"{old}^{{tree}}", "-m", "rewritten old base")
        self.target = self.git(self.upstream, "commit-tree", f"{self.target}^{{tree}}", "-p", rewritten_base, "-m", "release on rewritten history")
        self.git(self.upstream, "reset", "--hard", self.target)
        self.git(self.upstream, "tag", "-f", "v1.14.1", self.target)
        os.environ["UPSTREAM_COMMIT"] = self.target
        result = subprocess.run(["git", "merge-base", "--is-ancestor", old, self.target], cwd=self.upstream)
        self.assertEqual(result.returncode, 1)

    def test_reset_testing_does_not_change_the_release_we_fetch(self):
        self.git(self.upstream, "switch", "-c", "testing")
        self.git(self.upstream, "reset", "--hard", "v1.14.0")
        self.prepare()
        self.git(self.fork, "merge-base", "--is-ancestor", self.target, "HEAD")
        self.assertEqual((self.fork / "core.go").read_text(), "new upstream core\n")

    def test_rewritten_history_keeps_fork_changes_and_upstream_deletions(self):
        self.rewrite_upstream_history()
        before = self.git(self.fork, "rev-parse", "HEAD")
        self.prepare()
        self.git(self.fork, "merge-base", "--is-ancestor", before, "HEAD")
        self.git(self.fork, "merge-base", "--is-ancestor", self.target, "HEAD")
        self.assertEqual((self.fork / "udpflow.go").read_text(), "fork feature\n")
        self.assertEqual((self.fork / "core.go").read_text(), "new upstream core\n")
        self.assertFalse((self.fork / "obsolete.txt").exists())
        self.assertEqual((self.fork / ".github/workflows/build.yml").read_text(), "udpflow workflow\n")
        self.assertEqual(json.loads((self.fork / "release/udpflow.json").read_text())["upstream_commit"], self.target)

    def test_rewritten_history_keeps_local_edits_across_an_upstream_rename(self):
        self.git(self.upstream, "mv", "rename.txt", "renamed.txt")
        self.target = self.commit(self.upstream, "upstream rename")
        local_content = (self.fork / "rename.txt").read_text().replace("line 7\n", "udpflow edit\n")
        (self.fork / "rename.txt").write_text(local_content)
        self.commit(self.fork, "local edit")
        self.rewrite_upstream_history()
        self.prepare()
        self.assertFalse((self.fork / "rename.txt").exists())
        self.assertEqual((self.fork / "renamed.txt").read_text(), local_content)

    def test_rewritten_history_conflict_leaves_head_and_files_unchanged(self):
        self.rewrite_upstream_history()
        (self.fork / "core.go").write_text("fork changed the same line\n")
        before = self.commit(self.fork, "fork core change")
        with self.assertRaisesRegex(ValueError, "merge needs review"):
            self.prepare()
        self.assertEqual(self.git(self.fork, "rev-parse", "HEAD"), before)
        self.assertEqual((self.fork / "core.go").read_text(), "fork changed the same line\n")
        self.assertEqual(self.git(self.fork, "diff", "--name-only", "--diff-filter=U"), "")

    def test_next_release_can_follow_a_previously_rewritten_release(self):
        self.rewrite_upstream_history()
        self.prepare()
        previous = self.git(self.fork, "rev-parse", "HEAD")
        # A new runner starts with the committed tree, without the build-only
        # Android patch/version edits left by the previous preparation.
        next_fork = Path(self.temp.name) / "next-fork"
        self.git(self.fork, "clone", str(self.fork), str(next_fork))
        self.fork = next_fork
        (self.client / "version.properties").write_text("VERSION_NAME=1.14.2\nVERSION_CODE=732\nGO_VERSION=go1.26.7\n")
        self.client_commit = self.commit(self.client, "client 1.14.2")
        (self.upstream / "core.go").write_text("second upstream update\n")
        self.target = self.commit(self.upstream, "core 1.14.2")
        self.git(self.upstream, "tag", "v1.14.2")
        os.environ.update(UPSTREAM_TAG="v1.14.2", UPSTREAM_COMMIT=self.target, GITHUB_RUN_NUMBER="62")
        self.prepare()
        self.git(self.fork, "merge-base", "--is-ancestor", previous, "HEAD")
        self.git(self.fork, "merge-base", "--is-ancestor", self.target, "HEAD")
        self.assertEqual((self.fork / "core.go").read_text(), "second upstream update\n")
        self.assertEqual((self.fork / "udpflow.go").read_text(), "fork feature\n")
        self.assertFalse((self.fork / "obsolete.txt").exists())
        self.assertEqual(release.properties(self.fork / "clients/android/version.properties")["VERSION_NAME"], "1.14.2-udpflow")

    def test_uncommitted_edits_are_not_overwritten_or_included_in_release(self):
        before = self.git(self.fork, "rev-parse", "HEAD")
        for staged in (False, True):
            with self.subTest(staged=staged):
                (self.fork / "core.go").write_text("unfinished local edit\n")
                if staged:
                    self.git(self.fork, "add", "core.go")
                with self.assertRaises(subprocess.CalledProcessError):
                    self.prepare()
                self.assertEqual(self.git(self.fork, "rev-parse", "HEAD"), before)
                self.assertEqual((self.fork / "core.go").read_text(), "unfinished local edit\n")
                self.assertFalse((Path(self.temp.name) / "udpflow-source.json").exists())


if __name__ == "__main__":
    unittest.main()
