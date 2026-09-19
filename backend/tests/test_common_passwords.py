import pytest

from app.core.common_passwords import is_common_password


@pytest.mark.parametrize(
    "password",
    [
        "iloveyou",
        "111111111111",
        "aaaaaaaaaaaa",
        "abcdefghijkl",
        "qwertyuiop",
        "PASSWORD1",  # case-insensitive match
    ],
)
def test_flags_common_or_patterned_passwords(password):
    assert is_common_password(password) is True


@pytest.mark.parametrize(
    "password",
    [
        "Xk9#mQ2vLp7$Wz",
        "correct-horse-battery-staple-42",
        "Tr0picalFr00t!9x",
    ],
)
def test_allows_strong_passwords(password):
    assert is_common_password(password) is False
