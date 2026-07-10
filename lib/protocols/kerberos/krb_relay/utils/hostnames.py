from urllib.parse import urlparse

_UNICODE_DOT = "\u2024"
_CIRCLED_UPPER = 0x24B6
_CIRCLED_LOWER = 0x24D0


def parse_target(target: str) -> str:
    return urlparse(target).hostname or ""


def unicode_hostname(hostname: str) -> str:
    if not hostname:
        return hostname

    parts = hostname.split(".", 1)
    label = parts[0]
    zone = parts[1] if len(parts) > 1 else ""

    result = []
    letter_count = 0
    for char in label:
        if char.isalpha():
            letter_count += 1
            if letter_count == 2:
                if char.isupper():
                    result.append(chr(_CIRCLED_UPPER + ord(char) - ord("A")))
                else:
                    result.append(chr(_CIRCLED_LOWER + ord(char) - ord("a")))
                continue
        result.append(char)

    converted = "".join(result)
    if zone:
        converted += _UNICODE_DOT + zone.replace(".", _UNICODE_DOT)
    return converted
