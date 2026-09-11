import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import udpflow_testing_release as release


class TestingReleaseTest(unittest.TestCase):
    def setUp(self):
        self.source = {
            "upstream_branch": "testing",
            "upstream_version": "1.15.0-alpha.2",
            "upstream_commit": "a" * 40,
            "android_client_commit": "b" * 40,
            "fork_revision": 1,
        }

    def test_snapshot_has_a_distinct_development_version(self):
        with patch.object(Path, "read_text", return_value=json.dumps(self.source)):
            source, version = release.snapshot()
        self.assertEqual(version, "1.15.0-alpha.2-udpflow.1")
        self.assertEqual(source, self.source)

    def test_snapshot_requires_immutable_pins_and_development_version(self):
        for key, value in (("upstream_branch", "stable"), ("upstream_commit", "testing"), ("android_client_commit", "dev"), ("upstream_version", "1.15.0"), ("fork_revision", True), ("fork_revision", 0)):
            with self.subTest(key=key, value=value), patch.object(Path, "read_text", return_value=json.dumps({**self.source, key: value})):
                with self.assertRaises(ValueError):
                    release.snapshot()

    def test_plan_uses_the_pin_and_does_not_require_an_official_release(self):
        for published in (False, True):
            with self.subTest(published=published), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                responses = [{"sha": self.source["upstream_commit"]}, {"draft": False, "prerelease": True} if published else None]
                with patch.object(release, "snapshot", return_value=(self.source, "1.15.0-alpha.2-udpflow.1")), patch.object(release, "api", side_effect=responses) as api, patch.dict(os.environ, GITHUB_REF="refs/heads/udpflow-testing", GITHUB_EVENT_NAME="push", GITHUB_REPOSITORY="example/fork", GITHUB_OUTPUT=str(output)):
                    release.plan()
                self.assertEqual(release.properties(output), {"build": "true", "publish": str(not published).lower()})
                self.assertEqual(api.call_args_list[0].args, (f"repos/SagerNet/sing-box/commits/{self.source['upstream_commit']}",))

    def test_plan_does_not_publish_from_stable_branch(self):
        with patch.object(release, "snapshot", return_value=(self.source, "version")), patch.object(release, "api") as api, patch.dict(os.environ, GITHUB_REF="refs/heads/udpflow", GITHUB_EVENT_NAME="push"):
            with self.assertRaisesRegex(ValueError, "udpflow-testing"):
                release.plan()
            api.assert_not_called()

    def test_pull_request_only_builds(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.object(release, "snapshot", return_value=(self.source, "version")), patch.object(release, "api") as api, patch.dict(os.environ, GITHUB_EVENT_NAME="pull_request", GITHUB_OUTPUT=str(output)):
                release.plan()
            self.assertEqual(release.properties(output), {"build": "true", "publish": "false"})
            api.assert_not_called()

    def test_testing_release_cannot_be_silently_promoted_to_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(release, "snapshot", return_value=(self.source, "version")), patch.object(release, "api", side_effect=[{"sha": "a" * 40}, {"draft": False, "prerelease": False}]), patch.dict(os.environ, GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/udpflow-testing", GITHUB_REPOSITORY="example/fork", GITHUB_OUTPUT=str(Path(directory) / "output")):
                with self.assertRaisesRegex(ValueError, "prerelease"):
                    release.plan()


if __name__ == "__main__":
    unittest.main()
