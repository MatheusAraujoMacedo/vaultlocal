"""Reject master passwords that show up in well-known breach/common-password
compilations (RockYou, HaveIBeenPwned top lists) or follow trivial patterns.

This is a curated subset, not the literal 14M-entry RockYou dump -- embedding
that verbatim is impractical and unnecessary. The entries below are the
consistently top-ranked passwords across published breach analyses, which is
where brute-force and credential-stuffing tools start.
"""

_LITERAL_COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "1234567", "12345", "1234567890",
    "1234", "123123", "123321", "111111", "000000", "666666", "121212",
    "112233", "654321", "222222", "777777", "888888", "999999",
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "iloveyou", "princess", "sunshine", "shadow", "monkey", "monkey1",
    "dragon", "master", "master1", "letmein", "login", "admin",
    "administrator", "welcome", "welcome1", "qwerty", "qwerty123",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "abc123", "abcd1234",
    "trustno1", "starwars", "superman", "batman", "spiderman",
    "football", "baseball", "basketball", "soccer", "hockey",
    "whatever", "freedom", "ninja", "mustang", "michael", "jennifer",
    "jordan23", "hunter2", "access", "flower", "hottie", "loveme",
    "charlie", "donald", "andrew", "daniel", "matthew", "joshua",
    "george", "thomas", "robert", "buster", "harley", "ranger",
    "tigger", "soccer1", "cheese", "summer", "winter", "autumn",
    "1q2w3e4r", "1qaz2wsx", "qazwsx", "zaq12wsx", "q1w2e3r4",
    "rockyou", "changeme", "letmein1", "iloveyou1", "senha",
    "senha123", "brasil", "brasil123", "vasco", "flamengo", "corinthians",
    "palmeiras", "internacional", "gremio", "12345678910",
    "aaaaaa", "bbbbbb", "111222", "asdf1234", "test1234", "temp1234",
}

_KEYBOARD_ROWS = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def _is_sequential(lowered: str) -> bool:
    if len(lowered) < 6:
        return False
    ascending = all(
        ord(lowered[i + 1]) - ord(lowered[i]) == 1 for i in range(len(lowered) - 1)
    )
    descending = all(
        ord(lowered[i]) - ord(lowered[i + 1]) == 1 for i in range(len(lowered) - 1)
    )
    return ascending or descending


def _is_single_character(lowered: str) -> bool:
    return len(set(lowered)) == 1


def _is_keyboard_walk(lowered: str) -> bool:
    if len(lowered) < 6:
        return False
    for row in _KEYBOARD_ROWS:
        if lowered in row or lowered in row[::-1]:
            return True
    return False


def is_common_password(password: str) -> bool:
    lowered = password.strip().lower()
    if lowered in _LITERAL_COMMON_PASSWORDS:
        return True
    if _is_single_character(lowered):
        return True
    if _is_sequential(lowered):
        return True
    if _is_keyboard_walk(lowered):
        return True
    return False
