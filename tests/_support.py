"""Synthetic secret builders for tests.

Every vendor-shaped value is assembled at runtime. The point is not to hide
test structure; it is to keep secret-scanning pipelines from mistaking a
source literal for a live credential.
"""

import hashlib


def cat(*parts):
    return "".join(parts)


TOKEN_BASE = "Zx7Qa9Lm2Vp4Rs8Cw1Ye6Tb3Nu5Hd0Kj"
UPPER_BASE = "ZX7QA9LM2VP4RS8CW1YE6TB3NU5HD0KJ"
LOWER_HEX = "a9f3c7e1b5d208469cf0e7b1a3d598c2"
URLSAFE_BASE = "Zx7Qa9-Lm2_Vp4Rs8Cw1Ye6Tb3Nu5Hd0Kj"


def repeat_base(base, length):
    return (base * ((length // len(base)) + 1))[:length]


def seeded(length):
    return repeat_base(TOKEN_BASE, length)


def upper(length):
    return repeat_base(UPPER_BASE, length)


def lower_hex(length):
    return repeat_base(LOWER_HEX, length)


def urlsafe(length):
    return repeat_base(URLSAFE_BASE, length)


def fp(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def aws_access_key():
    return cat("A", "K", "I", "A") + upper(16)


def aws_session_key():
    return cat("A", "S", "I", "A") + upper(16)


def aws_secret_value():
    return seeded(38) + "+/"


def github_pat():
    return cat("g", "h", "p_") + seeded(36)


def github_fine_pat():
    return cat("github", "_pat_") + seeded(40) + "__"


def github_oauth():
    return cat("g", "h", "o_") + seeded(36)


def stripe_secret():
    return cat("s", "k", "_", "live", "_") + seeded(24)


def stripe_restricted():
    return cat("r", "k", "_", "test", "_") + seeded(24)


def stripe_publishable():
    return cat("p", "k", "_", "live", "_") + seeded(24)


def slack_webhook():
    return cat("https://hooks.slack", ".com/services/") + urlsafe(28)


def slack_token():
    return cat("x", "o", "x", "b", "-") + seeded(18)


def google_api_key():
    return cat("A", "I", "z", "a") + urlsafe(35)


def google_client_secret():
    return cat("G", "O", "C", "S", "P", "X", "-") + urlsafe(28)


def google_refresh_token():
    return cat("1", "/", "/0") + urlsafe(34)


def openai_key():
    return cat("s", "k", "-") + urlsafe(32)


def anthropic_key():
    return cat("s", "k", "-", "ant", "-") + urlsafe(32)


def huggingface_token():
    return cat("h", "f_") + seeded(34)


def npm_token():
    return cat("n", "p", "m_") + seeded(36)


def pypi_token():
    return cat("p", "y", "p", "i", "-") + urlsafe(44)


def docker_token():
    return cat("d", "c", "k", "r", "_pat_") + urlsafe(28)


def twilio_key():
    return cat("S", "K") + lower_hex(32)


def sendgrid_key():
    return cat("S", "G", ".") + urlsafe(20) + "." + urlsafe(20)


def discord_token():
    return urlsafe(24) + "." + urlsafe(6) + "." + urlsafe(28)


def telegram_token():
    return "987654321" + ":" + urlsafe(34)


def mailgun_key():
    return cat("k", "e", "y", "-") + lower_hex(32)


def mailchimp_key():
    return lower_hex(32) + cat("-", "u", "s", "11")


def square_token():
    return cat("s", "q", "0", "atp", "-") + urlsafe(28)


def sonarqube_token():
    return cat("s", "q", "u_") + seeded(40)


def hex32():
    return lower_hex(32)


def db_uri():
    password = seeded(18)
    return "postgresql://service:{}@db.example.invalid/app".format(password), password


def jwt_token():
    return cat("e", "y", "J") + urlsafe(12) + "." + urlsafe(12) + "." + urlsafe(12)


def pem_private_key(kind=""):
    begin = cat("-----", "BEGIN ", kind, "PRIVATE KEY", "-----")
    end = cat("-----", "END ", kind, "PRIVATE KEY", "-----")
    body = "\n" + urlsafe(48) + "\n" + urlsafe(48) + "\n"
    return begin + body + end


def high_entropy_value(length=48):
    return urlsafe(length)


def card_number():
    return cat("4", "1" * 15)


def formatted_card_number():
    digits = card_number()
    return " ".join(digits[index:index + 4] for index in range(0, len(digits), 4))


def ssn_value():
    return cat("137", "-", "42", "-", "8965")
