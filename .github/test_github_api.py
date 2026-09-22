import http.client
import io
import json
import os
import unittest
import urllib.error
from unittest.mock import patch

import udpflow_release as release


class TruncatedResponse(io.BytesIO):
    def read(self, *args):
        raise http.client.IncompleteRead(b"partial", 100)


class GitHubAPITest(unittest.TestCase):
    def setUp(self):
        token = patch.dict(os.environ, GH_TOKEN="test-token")
        token.start()
        self.addCleanup(token.stop)
        sleep = patch.object(release.time, "sleep")
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    def test_truncated_response_body_is_closed_and_retried(self):
        truncated = TruncatedResponse()
        with patch.object(release.urllib.request, "urlopen", side_effect=[truncated, io.BytesIO(b'{"ok": true}')]) as request:
            self.assertEqual(release.api("repos/example/repo"), {"ok": True})
        self.assertTrue(truncated.closed)
        self.assertEqual(request.call_count, 2)
        self.sleep.assert_called_once_with(1)

    def test_transient_http_connection_and_json_failures_are_retried(self):
        failures = [
            urllib.error.HTTPError("https://api.github.com/graphql", 503, "unavailable", {}, None),
            urllib.error.URLError("connection failed"),
            http.client.RemoteDisconnected("connection closed"),
            TimeoutError("read timed out"),
            ConnectionResetError("connection reset"),
        ]
        for failure in failures:
            with self.subTest(failure=failure), patch.object(release.urllib.request, "urlopen", side_effect=[failure, io.BytesIO(b'{}')]) as request:
                self.assertEqual(release.api("graphql", data={"query": "query { viewer { login } }"}), {})
                self.assertEqual(request.call_count, 2)
        with patch.object(release.urllib.request, "urlopen", side_effect=[io.BytesIO(b'{'), io.BytesIO(b'{}')]):
            self.assertEqual(release.api("repos/example/repo"), {})

    def test_retries_are_bounded_and_exhaustion_is_visible(self):
        with patch.object(release.urllib.request, "urlopen", side_effect=TimeoutError("read timed out")) as request:
            with self.assertRaisesRegex(ValueError, "failed after 3 attempts"):
                release.api("repos/example/repo")
        self.assertEqual(request.call_count, 3)
        self.assertEqual([call.args[0] for call in self.sleep.call_args_list], [1, 2])

    def test_not_found_and_permission_errors_are_not_retried(self):
        for code, missing_ok in ((404, True), (404, False), (401, False), (403, False)):
            error = urllib.error.HTTPError("https://api.github.com/test", code, "failure", {}, None)
            with self.subTest(code=code, missing_ok=missing_ok), patch.object(release.urllib.request, "urlopen", side_effect=error) as request:
                if missing_ok:
                    self.assertIsNone(release.api("test", missing_ok=True))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        release.api("test")
                request.assert_called_once()
        self.sleep.assert_not_called()

    def test_graphql_payload_is_json_and_get_remains_a_get(self):
        payload = {"query": "query($cursor: String) { viewer { login } }", "variables": {"cursor": None}}
        with patch.object(release.urllib.request, "urlopen", side_effect=[io.BytesIO(b'{}'), io.BytesIO(b'{}')]) as request:
            release.api("graphql", data=payload)
            post = request.call_args.args[0]
            self.assertEqual(post.get_method(), "POST")
            self.assertEqual(json.loads(post.data), payload)
            self.assertEqual(post.get_header("Content-type"), "application/json")
            release.api("repos/example/repo")
            get = request.call_args.args[0]
            self.assertEqual(get.get_method(), "GET")
            self.assertIsNone(get.data)


if __name__ == "__main__":
    unittest.main()
