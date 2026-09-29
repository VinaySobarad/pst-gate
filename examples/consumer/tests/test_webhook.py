from main import verify_signature


def test_accepts_valid_hmac():
    body = b'{"ok":true}'
    secret = b"test-secret"
    import hashlib
    import hmac

    sig = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    assert verify_signature(secret, body, sig) is True


def test_rejects_garbage():
    assert verify_signature(b"wrong-secret", b"{}", "nope") is False
