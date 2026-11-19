"""A very small PDF writer - enough for a branded monthly report, no dependencies.

NetSentinel ships without pip installs, so reportlab is not available on a hotel PC. This
module writes a valid PDF 1.4 file with the standard Helvetica fonts: text, rules, filled
bars and simple tables, wrapped using the real Helvetica advance widths.
"""

from __future__ import annotations

import zlib

# Helvetica advance widths for printable ASCII (units per 1000 em, from the Adobe AFM)
_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
      556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
      1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
      667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
      333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
      556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]

A4 = (595.28, 841.89)


def text_width(text, size, bold=False):
    total = 0
    for ch in text:
        code = ord(ch)
        total += _W[code - 32] if 32 <= code <= 126 else 556
    return total * size / 1000.0 * (1.03 if bold else 1.0)


def _esc(text):
    return (text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)"))


class Doc:
    """Build pages of text and shapes, then write a PDF."""

    def __init__(self, size=A4, margin=48):
        self.size = size
        self.margin = margin
        self.pages = []
        self.ops = []
        self.y = size[1] - margin
        self.width = size[0] - 2 * margin

    # ------------------------------------------------------------ page ops --
    def new_page(self):
        if self.ops:
            self.pages.append("\n".join(self.ops))
        self.ops = []
        self.y = self.size[1] - self.margin

    def space(self, amount):
        self.y -= amount

    def room(self, needed):
        return self.y - needed > self.margin

    def ensure(self, needed):
        if not self.room(needed):
            self.new_page()
            return True
        return False

    # --------------------------------------------------------------- shapes --
    def text(self, x, y, value, size=10, bold=False, grey=0.0):
        font = "F2" if bold else "F1"
        self.ops.append(f"BT /{font} {size} Tf {grey:.3f} g "
                        f"1 0 0 1 {x:.2f} {y:.2f} Tm ({_esc(str(value))}) Tj ET")

    def line(self, x1, y1, x2, y2, grey=0.8, width=0.6):
        self.ops.append(f"{grey:.3f} G {width} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def rect(self, x, y, w, h, grey=0.5, fill=True):
        op = "f" if fill else "S"
        self.ops.append(f"{grey:.3f} g {x:.2f} {y:.2f} {w:.2f} {h:.2f} re {op}")

    # ---------------------------------------------------------------- text ---
    def wrap(self, value, size, width=None, bold=False):
        width = width or self.width
        words = str(value).split()
        lines, current = [], ""
        for word in words:
            trial = (current + " " + word).strip()
            if text_width(trial, size, bold) <= width:
                current = trial
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines or [""]

    def para(self, value, size=10, bold=False, leading=None, grey=0.0, gap=4, x=None,
             width=None):
        leading = leading or size * 1.35
        for line in self.wrap(value, size, width, bold):
            self.ensure(leading)
            self.text(x if x is not None else self.margin, self.y - size, line,
                      size, bold, grey)
            self.y -= leading
        self.y -= gap

    def heading(self, value, size=13, gap_before=10):
        self.space(gap_before)
        self.ensure(size * 2)
        self.text(self.margin, self.y - size, value, size, True, 0.15)
        self.y -= size * 1.3
        self.line(self.margin, self.y, self.margin + self.width, self.y, 0.75, 0.8)
        self.y -= 8

    # --------------------------------------------------------------- tables --
    def table(self, headers, rows, fracs, size=9, header_bg=0.88, pad=5):
        widths = [f * self.width for f in fracs]
        row_h = size * 1.5 + pad
        self.ensure(row_h * 2)
        x = self.margin
        self.rect(self.margin, self.y - row_h + 4, self.width, row_h - 2, header_bg, True)
        for i, head in enumerate(headers):
            self.text(x + 4, self.y - size - 1, head, size, True, 0.15)
            x += widths[i]
        self.y -= row_h
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                cells.append(self.wrap(cell, size, widths[i] - 8))
            height = max(len(c) for c in cells) * (size * 1.3) + pad
            self.ensure(height)
            x = self.margin
            for i, lines in enumerate(cells):
                for j, line in enumerate(lines):
                    self.text(x + 4, self.y - size - j * size * 1.3, line, size, False, 0.1)
                x += widths[i]
            self.y -= height
            self.line(self.margin, self.y + 3, self.margin + self.width, self.y + 3, 0.9, 0.4)
        self.y -= 6

    def bar(self, label, fraction, value, size=9, colour=0.35):
        """One horizontal bar with a label on the left and a value on the right."""
        self.ensure(size * 2.2)
        self.text(self.margin, self.y - size, label, size, False, 0.15)
        bar_x = self.margin + 150
        bar_w = self.width - 230
        self.rect(bar_x, self.y - size + 1, bar_w, size - 1, 0.92, True)
        filled = max(0.0, min(1.0, fraction)) * bar_w
        if filled > 0.4:
            self.rect(bar_x, self.y - size + 1, filled, size - 1, colour, True)
        self.text(bar_x + bar_w + 8, self.y - size, value, size, False, 0.15)
        self.y -= size * 2.0

    # ---------------------------------------------------------------- write --
    def build(self):
        if self.ops:
            self.pages.append("\n".join(self.ops))
            self.ops = []
        objects = []

        def add(obj):
            objects.append(obj)
            return len(objects)

        font1 = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                    "/Encoding /WinAnsiEncoding >>")
        font2 = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                    "/Encoding /WinAnsiEncoding >>")
        pages_id_placeholder = len(objects) + 1 + 2 * len(self.pages)
        kids = []
        page_objs = []
        for body in self.pages:
            data = zlib.compress(body.encode("latin-1", "replace"))
            stream_id = len(objects) + 2
            content_id = add(f"<< /Length {len(data)} /Filter /FlateDecode >>\nstream\n"
                             + data.decode("latin-1") + "\nendstream")
            page_id = add(f"<< /Type /Page /Parent {pages_id_placeholder} 0 R "
                          f"/MediaBox [0 0 {self.size[0]:.2f} {self.size[1]:.2f}] "
                          f"/Resources << /Font << /F1 {font1} 0 R /F2 {font2} 0 R >> >> "
                          f"/Contents {content_id} 0 R >>")
            kids.append(page_id)
            page_objs.append(page_id)
            _ = stream_id
        pages_id = add(f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] "
                       f"/Count {len(kids)} >>")
        catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for i, obj in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n{obj}\nendobj\n".encode("latin-1", "replace")
        xref_at = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
                f"startxref\n{xref_at}\n%%EOF\n").encode()
        return bytes(out)
