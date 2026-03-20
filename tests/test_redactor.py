from app.core.redactor import redact


def test_phone_number_redacted():
    assert "[PHONE_REDACTED]" in redact("Call me at 9876543210")


def test_email_redacted():
    assert "[EMAIL_REDACTED]" in redact("Email me at test@example.com")


def test_openai_api_key_redacted():
    assert "[API_KEY_REDACTED]" in redact("My key is sk-abcdefghijklmnopqrstuvwxyz123456")


def test_groq_api_key_redacted():
    assert "[API_KEY_REDACTED]" in redact("My key is gsk_abcdefghijklmnopqrstuvwxyz123456")


def test_indian_city_redacted():
    assert "[LOCATION_REDACTED]" in redact("I live in Pune")


def test_mumbai_redacted():
    assert "[LOCATION_REDACTED]" in redact("I am from Mumbai")


def test_clean_text_unchanged():
    text = "What is the weather like today?"
    assert redact(text) == text


def test_password_redacted():
    assert "[PASSWORD_REDACTED]" in redact("My password=secret123")