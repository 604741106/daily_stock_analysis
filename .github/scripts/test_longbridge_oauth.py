"""Offline credential handling checks; never load a user's real SDK cache."""

import base64
import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

from check_longbridge_oauth import mask, secret_box, validate_cache


class OAuthCacheChecks(unittest.TestCase):
    def setUp(self):
        self.cache = {"client_id": "test-client", "access_token": "test-access", "refresh_token": "test-refresh"}

    def test_rejects_cache_from_another_client(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_cache(json.dumps(self.cache).encode(), "another-client")

    def test_requires_refresh_credential(self):
        self.cache.pop("refresh_token")
        with self.assertRaisesRegex(ValueError, "required token"):
            validate_cache(json.dumps(self.cache).encode(), "test-client")

    def test_mask_commands_escape_control_characters(self):
        self.cache["access_token"] = "test%\r\naccess"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            mask(self.cache)
        self.assertEqual(output.getvalue().splitlines(), ["::add-mask::test%25%0D%0Aaccess", "::add-mask::test-refresh"])

    def test_rejects_wrong_length_encryption_key(self):
        key = base64.b64encode(b"too-short").decode()
        with patch.dict(os.environ, {"LONGBRIDGE_OAUTH_CACHE_ENCRYPTION_KEY": key}):
            with self.assertRaisesRegex(ValueError, "32-byte"):
                secret_box()


if __name__ == "__main__":
    unittest.main()
