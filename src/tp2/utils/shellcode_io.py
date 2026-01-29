from __future__ import annotations

import os
from typing import List


def _parse_c_style_shellcode(text: str) -> bytes:
    out = bytearray()
    i = 0
    t = text
    while i < len(t):
        if t[i] == "\\" and i + 3 < len(t) and t[i + 1] == "x":
            h = t[i + 2 : i + 4]
            try:
                out.append(int(h, 16))
                i += 4
                continue
            except Exception:
                pass
        out.append(ord(t[i]))
        i += 1
    return bytes(out)


def _parse_hex_stream(text: str) -> bytes:
    cleaned = "".join(c for c in text if c.isalnum())
    if len(cleaned) % 2 != 0:
        cleaned = cleaned[:-1]
    out = bytearray()
    for i in range(0, len(cleaned), 2):
        try:
            out.append(int(cleaned[i : i + 2], 16))
        except Exception:
            break
    return bytes(out)


def read_shellcodes_from_file(path: str) -> List[bytes]:
    if not path or not os.path.exists(path):
        return []

    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception:
        return []

    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    candidates: List[bytes] = []
    if text:
        if "\\x" in text:
            candidates.append(_parse_c_style_shellcode(text))
        else:
            b = _parse_hex_stream(text)
            if b:
                candidates.append(b)

    if not candidates and raw:
        candidates.append(raw)

    return [c for c in candidates if c]
