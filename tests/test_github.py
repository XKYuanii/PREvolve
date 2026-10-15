import hashlib
import hmac
import unittest

from evoagent.serving.github import verify_signature


class GitHubSignatureTests(unittest.TestCase):
    def test_signature_verification(self):
        body = b'{"ok":true}'
        signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_signature("secret", body, signature))
        self.assertFalse(verify_signature("wrong", body, signature))

    def test_non_ascii_signature_is_rejected_without_raising(self):
        for signature in ("sha256=" + "é" * 64, "sha256=" + "０" * 64):
            with self.subTest(signature=signature):
                self.assertFalse(verify_signature("secret", b'{}', signature))

    def test_missing_secret_and_malformed_signatures_are_rejected(self):
        body = b'{"ok":true}'
        valid = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertFalse(verify_signature("", body, valid))
        for signature in ("", "sha1=" + "0" * 40, "sha256=", valid[:-1], valid + "0"):
            with self.subTest(signature=signature):
                self.assertFalse(verify_signature("secret", body, signature))

    def test_signature_does_not_authenticate_a_modified_payload(self):
        signature = "sha256=" + hmac.new(b"secret", b'{"ok":true}', hashlib.sha256).hexdigest()
        self.assertFalse(verify_signature("secret", b'{"ok":false}', signature))


if __name__ == "__main__":
    unittest.main()

