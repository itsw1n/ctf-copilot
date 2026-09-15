from __future__ import annotations

import math
from ..scoring import quality


def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    if rails < 2 or rails >= len(ciphertext):
        return ciphertext
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    route = [pattern[index % len(pattern)] for index in range(len(ciphertext))]
    counts = [route.count(rail) for rail in range(rails)]
    buckets = []
    offset = 0
    for count in counts:
        buckets.append(list(ciphertext[offset:offset + count]))
        offset += count
    return "".join(buckets[rail].pop(0) for rail in route)


def columnar_decrypt(ciphertext: str, columns: int) -> str:
    if columns < 2 or columns >= len(ciphertext):
        return ciphertext
    rows = math.ceil(len(ciphertext) / columns)
    short = rows * columns - len(ciphertext)
    sizes = [rows - (1 if index >= columns - short and short else 0) for index in range(columns)]
    chunks = []
    offset = 0
    for size in sizes:
        chunks.append(ciphertext[offset:offset + size])
        offset += size
    return "".join(chunks[column][row] for row in range(rows) for column in range(columns) if row < len(chunks[column]))


def candidates(value: str, max_width: int = 12) -> list[tuple[float, str, int, str]]:
    rows = []
    for rails in range(2, min(10, len(value) - 1) + 1):
        text = rail_fence_decrypt(value, rails)
        rows.append((quality(text), "rail-fence", rails, text))
    for width in range(2, min(max_width, len(value) - 1) + 1):
        text = columnar_decrypt(value, width)
        rows.append((quality(text), "columnar", width, text))
    return sorted(rows, reverse=True)[:8]
