import re
import unicodedata


# Zero-width and invisible characters attackers use to hide payloads
INVISIBLE_CHARS_PATTERN = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f'  # Zero-width spaces/joins
    r'\u202a\u202b\u202c\u202d\u202e'   # Directional overrides
    r'\u2060\u2061\u2062\u2063\u2064'   # Word joiners
    r'\ufeff'                            # BOM / zero-width no-break
    r'\u00ad'                            # Soft hyphen
    r']'
)


def normalize(text: str) -> str:
    """
    Clean text before it reaches the security classifier or LLM.

    Steps:
    1. NFKC unicode normalization (converts lookalikes: ① → 1, ﬁ → fi)
    2. Strip invisible/zero-width characters
    3. Collapse excessive whitespace
    4. Strip leading/trailing whitespace
    """
    if not text:
        return text

    # Step 1 — NFKC normalization
    # Converts visually similar characters to their standard form
    # e.g. ａ → a, ２ → 2, ＩＧＮＯＲＥinstructions → IGNOREinstructions
    text = unicodedata.normalize("NFKC", text)

    # Step 2 — Strip invisible characters
    text = INVISIBLE_CHARS_PATTERN.sub("", text)

    # Step 3 — Collapse multiple spaces/newlines into single space
    text = re.sub(r'[ \t]+', ' ', text)

    # Step 4 — Strip edges
    text = text.strip()

    return text