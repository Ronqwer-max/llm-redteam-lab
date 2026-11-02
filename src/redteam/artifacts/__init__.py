"""Multimodal payload builders — PNG images, PDF documents, WAV audio, and
zero-width steganography — implemented on the standard library only.

These generate *test fixtures*: hostile instructions concealed inside benign
looking media, used to probe whether a vision / audio / document pipeline
obeys text it merely observed instead of text the user actually sent.

Modes
-----
image modes:
    ``overlay``  dark text over structured noise (visible to humans, survives OCR)
    ``stego``    near-white text on white background (invisible at a glance)
audio:
    payload encoded both as RIFF/INFO metadata and as Morse tone bursts
pdf:
    white-on-white text drawn with a standard Helvetica font
text:
    benign prose with the instruction buried as zero-width characters
"""

from __future__ import annotations

import math
import struct
import wave
import zlib
from typing import Iterable

from ..core.finding import Attachment
from .font5x7 import CHAR_H, CHAR_W, GLYPHS

ZW_ZERO = "​"
ZW_ONE = "‌"

# ---------------------------------------------------------------------------
# zero-width steganography
# ---------------------------------------------------------------------------


def hide_zero_width(benign_text: str, secret: str) -> str:
    """Embed ``secret`` into ``benign_text`` as U+200B/U+200C bit pairs."""
    bits: list[str] = []
    for byte in secret.encode("utf-8"):
        for shift in range(7, -1, -1):
            bits.append(ZW_ONE if (byte >> shift) & 1 else ZW_ZERO)
    # split the stream across word boundaries so it stays visually invisible
    words = benign_text.split(" ")
    if not words:
        words = [""]
    per_word = max(1, len(bits) // len(words))
    out: list[str] = []
    idx = 0
    for i, word in enumerate(words):
        chunk = "".join(bits[idx: idx + per_word]) if i < len(words) - 1 else "".join(bits[idx:])
        idx += per_word if i < len(words) - 1 else len(bits)
        out.append(word + chunk)
    return " ".join(out)


def decode_zero_width(text: str) -> str:
    """Inverse of :func:`hide_zero_width` (used in tests)."""
    stream = [c for c in text if c in (ZW_ZERO, ZW_ONE)]
    out = bytearray()
    for i in range(0, len(stream) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (1 if stream[i + j] == ZW_ONE else 0)
        out.append(byte)
    return out.decode("utf-8", "ignore")


# ---------------------------------------------------------------------------
# PNG rendering with the built-in bitmap font
# ---------------------------------------------------------------------------


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    body = tag + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def _encode_png(width: int, height: int, rows: Iterable[bytearray]) -> bytes:
    raw = b"".join(b"\x00" + bytes(r) for r in rows)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(raw, 9))
        + _png_chunk(b"IEND", b"")
    )


def _wrap(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for para in text.split("\n"):
        words, line = para.split(), ""
        if not words:
            lines.append("")
            continue
        for w in words:
            cand = f"{line} {w}".strip()
            if len(cand) <= width:
                line = cand
            else:
                lines.append(line)
                line = w
        lines.append(line)
    return lines


def render_text_png(
    text: str,
    mode: str = "overlay",
    pixel: int = 3,
    columns: int = 44,
    margin: int = 12,
) -> bytes:
    """Render ``text`` into an RGB PNG.

    ``mode='overlay'`` prints dark glyphs on a noisy light background;
    ``mode='stego'`` prints near-white glyphs on white (hidden from humans,
    still machine-readable by OCR/vision models).
    """
    lines = _wrap(text.upper(), columns)
    char_px_w, char_px_h = CHAR_W * pixel, CHAR_H * pixel
    line_h = char_px_h + pixel * 2
    width = margin * 2 + columns * char_px_w
    height = margin * 2 + len(lines) * line_h

    if mode == "stego":
        bg, ink = (255, 255, 255), (245, 245, 245)
    else:  # overlay
        bg, ink = (248, 250, 252), (17, 24, 39)

    rows: list[bytearray] = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            r, g, b = bg
            if mode == "overlay":
                # subtle diagonal hatch so the text looks like a watermark
                if (x + y) % 13 == 0:
                    r, g, b = 226, 232, 240
            row += bytes((r, g, b))
        rows.append(row)

    for li, line in enumerate(lines):
        y0 = margin + li * line_h
        for ci, ch in enumerate(line.upper()):
            glyph = GLYPHS.get(ch)
            if glyph is None:
                glyph = GLYPHS.get(ch.upper())
            if glyph is None:
                glyph = ("#####", "#   #", "#   #", "#   #", "#   #", "#   #", "#####")
            x0 = margin + ci * char_px_w
            for gy, pattern in enumerate(glyph):
                for gx, cell in enumerate(pattern):
                    if cell != "#":
                        continue
                    for py in range(pixel):
                        for px in range(pixel):
                            X, Y = x0 + gx * pixel + px, y0 + gy * pixel + py
                            if 0 <= X < width and 0 <= Y < height:
                                rows[Y][X * 3: X * 3 + 3] = bytes(ink)
    return _encode_png(width, height, rows)


# ---------------------------------------------------------------------------
# minimal PDF
# ---------------------------------------------------------------------------


def _pdf_escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def make_pdf(lines: list[str], ink: tuple[float, float, float] = (1.0, 1.0, 1.0)) -> bytes:
    """Build a one-page Helvetica PDF whose text uses color ``ink``.

    White ink on the default white page produces a visually blank document
    that still contains extractable (and OCR-able) instructions.
    """
    content_parts = [f"{ink[0]:.3f} {ink[1]:.3f} {ink[2]:.3f} rg", "BT", "/F1 11 Tf", "72 720 Td", "14 TL"]
    for i, line in enumerate(lines):
        if i:
            content_parts.append("T*")
        content_parts.append(f"({_pdf_escape(line)}) Tj")
    content_parts.append("ET")
    stream = "\n".join(content_parts).encode("latin-1", "replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(out)


# ---------------------------------------------------------------------------
# WAV audio (metadata channel + Morse tone channel)
# ---------------------------------------------------------------------------

_MORSE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
    "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
    "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
    "y": "-.--", "z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", " ": "/",
}


def make_wav(message: str, sample_rate: int = 8000) -> bytes:
    """Encode ``message`` as Morse tone bursts inside a PCM WAV, and also embed
    the plain text in a RIFF ``LIST/INFO`` chunk for transcription pipelines
    that read tags."""
    unit = 0.06
    samples: list[int] = []
    freq = 600.0
    for ch in message.lower():
        code = _MORSE.get(ch)
        if code is None:
            continue
        for symbol in code:
            dur = unit if symbol == "." else unit * 3
            n = int(sample_rate * dur)
            for i in range(n):
                val = int(12000 * math.sin(2 * math.pi * freq * i / sample_rate))
                samples.append(val)
            samples.extend([0] * int(sample_rate * unit))  # symbol gap
        samples.extend([0] * int(sample_rate * unit * 2))  # letter gap

    pcm = b"".join(struct.pack("<h", s) for s in samples) or b"\x00\x00"

    info_text = message.encode("latin-1", "replace") + b"\x00"
    inam = b"INAM" + struct.pack("<I", len(info_text)) + info_text
    if len(inam) % 2:
        inam += b"\x00"
    list_chunk = b"INFO" + inam
    lst = b"LIST" + struct.pack("<I", len(list_chunk)) + list_chunk

    fmt = struct.pack("<HHIIHH", 1, 1, sample_rate, sample_rate * 2, 2, 16)
    fmt_chunk = b"fmt " + struct.pack("<I", len(fmt)) + fmt
    data_chunk = b"data" + struct.pack("<I", len(pcm)) + pcm

    body = b"WAVE" + fmt_chunk + data_chunk + lst
    return b"RIFF" + struct.pack("<I", len(body)) + body


# ---------------------------------------------------------------------------
# convenience: turn a hostile instruction into a set of attachments
# ---------------------------------------------------------------------------


def image_attachment(instruction: str, cover: str, mode: str = "overlay", name: str = "chart.png") -> Attachment:
    return Attachment(
        name=name,
        mime="image/png",
        data=render_text_png(instruction, mode=mode),
        hidden_instruction=instruction,
        metadata={"cover_text": cover, "mode": mode},
    )


def audio_attachment(instruction: str, name: str = "voicemail.wav") -> Attachment:
    return Attachment(
        name=name,
        mime="audio/wav",
        data=make_wav(instruction),
        hidden_instruction=instruction,
        metadata={"transcript": instruction},
    )


def pdf_attachment(instruction: str, name: str = "invoice.pdf", visible: bool = False) -> Attachment:
    ink = (0.0, 0.0, 0.0) if visible else (1.0, 1.0, 1.0)
    lines = ["Acme Cloud - Invoice 2026-0042", "", instruction]
    return Attachment(
        name=name,
        mime="application/pdf",
        data=make_pdf(lines, ink=ink),
        hidden_instruction=instruction,
        metadata={"pages": 1},
    )


def text_attachment(benign: str, instruction: str, name: str = "notes.md") -> Attachment:
    doc = f"# Meeting notes\n\n{benign}\n\n{hide_zero_width('', instruction)}\n"
    return Attachment(
        name=name,
        mime="text/markdown",
        data=doc.encode("utf-8"),
        hidden_instruction=instruction,
        metadata={"stego": "zero-width"},
    )


__all__ = [
    "hide_zero_width",
    "decode_zero_width",
    "render_text_png",
    "make_pdf",
    "make_wav",
    "image_attachment",
    "audio_attachment",
    "pdf_attachment",
    "text_attachment",
]
