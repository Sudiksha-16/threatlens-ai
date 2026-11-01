import unittest
from backend.app.security.password import hash_password, verify_password, validate_password_strength
from backend.app.security.authentication import create_access_token
import jwt
from backend.app.config.settings import settings

class TestAuth(unittest.TestCase):
    def test_password_hashing(self):
        pwd = "SecureAnalystPassword2026!"
        hashed = hash_password(pwd)
        self.assertNotEqual(pwd, hashed)
        self.assertTrue(verify_password(pwd, hashed))
        self.assertFalse(verify_password("WrongPassword!", hashed))

    def test_password_strength_validation(self):
        valid, _ = validate_password_strength("validPass1")
        self.assertTrue(valid)

        invalid_short, _ = validate_password_strength("short1")
        self.assertFalse(invalid_short)

        invalid_no_digit, _ = validate_password_strength("onlyLettersHere")
        self.assertFalse(invalid_no_digit)

    def test_jwt_token_generation_and_decode(self):
        payload = {"sub": "analyst@threatlens.io", "user_id": "test-uuid-1234"}
        token = create_access_token(payload)
        self.assertIsInstance(token, str)

        decoded = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        self.assertEqual(decoded["sub"], "analyst@threatlens.io")
        self.assertEqual(decoded["user_id"], "test-uuid-1234")

if __name__ == "__main__":
    unittest.main()
