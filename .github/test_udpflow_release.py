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


if __name__ == "__main__":
    unittest.main()
