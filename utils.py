import re

# UUID (standard 36-char)
UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Mongo ObjectId (24 hex)
OBJECT_ID_REGEX = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)

# Pure numeric
NUMERIC_REGEX = re.compile(r"^\d+$")

# Long random-ish alphanumeric
LONG_ALNUM_REGEX = re.compile(r"^[a-zA-Z0-9]{20,}$")


def normalize_path(path: str) -> str:
    """
    Normalize dynamic segments into ':id'.

    This function:
    - Works segment-by-segment
    - Is deterministic
    - Does not depend on DB/history
    - Safe for Control-plane aggregation
    """

    if not path:
        return path

    segments = path.strip("/").split("/")
    normalized = []

    for seg in segments:
        if (
            UUID_REGEX.match(seg)
            or OBJECT_ID_REGEX.match(seg)
            or NUMERIC_REGEX.match(seg)
            or LONG_ALNUM_REGEX.match(seg)
        ):
            normalized.append(":id")
        else:
            normalized.append(seg)

    return "/" + "/".join(normalized)
