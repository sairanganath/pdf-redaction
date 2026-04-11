import fitz  # PyMuPDF
import re
import json
import os
import sys
from typing import List, Optional, Tuple

# =========================
# Config loading
# =========================

def load_extra_patterns(config_path: str = "redact_config.json") -> List[str]:
    if not os.path.exists(config_path):
        return []
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        eps = data.get("extra_patterns", [])
        return [p for p in eps if isinstance(p, str)]
    except Exception:
        return []

# =========================
# Known ID patterns
# =========================

BASE_PATTERNS = [
    r"\b[A-Z]{5}\d{4}[A-Z]\b",                                 # PAN
    r"\b\d{4}\s\d{4}\s\d{4}\b",                                # Aadhaar (spaced)
    r"\b\d{12}\b",                                             # 12-digit (Aadhaar-like)
    r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b",            # GSTIN
    r"\b[A-Z]{4}\d{5}[A-Z]\b",                                 # TAN
    r"\b[6-9]\d{9}\b",                                         # Indian mobile
    r"\b\+91\s?\d{10}\b",                                      # Mobile with +91
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",     # Email
    r"\b\d{6}\b",                                              # PIN code
    r"\b[A-Z]{4}0[A-Z\d]{6}\b",                                # IFSC
    # Receipt numbers (Rct/Rcpt/Receipt) + value
    r"\b(?:rct|rcpt|receipt)\s*(?:no|#|number)?\s*[:\-–]?\s*[A-Za-z0-9\-\/]{6,}\b",
]

SENSITIVE_KEYWORDS = [
    "pan", "aadhar", "aadhaar", "mobile", "phone", "email",
    "gst", "gstin", "tan", "cin", "account", "a/c", "ifsc",
    "signature", "sign", "proprietor", "director", "partner",
    "authorized signatory", "authorised signatory", "customer id",
    "client id", "ref no", "reference no", "license", "licence",
    "registration", "reg no", "uin", "udyam", "msme", "uan", "pf", "esic",
    "receipt", "rcpt", "rct"
]

ID_KEYWORDS = [
    "id", "id no", "id#", "no", "number", "ref", "reference",
    "account", "a/c", "acc", "customer", "client",
    "licence", "license", "dl", "reg", "registration",
    "policy", "folio", "member", "employee", "emp",
    "gst", "gstin", "pan", "tan", "cin", "uin", "msme", "udyam",
    "passport", "voter", "aadhaar", "aadhar", "ssn",
    "receipt", "rcpt", "rct"
]

# =========================
# Name detection (no titles needed)
# =========================

COMPANY_TOKENS = {
    "PVT", "PVT.", "PRIVATE", "LTD", "LTD.", "LIMITED", "LLP", "INC", "CO",
    "CO.", "COMPANY", "LLC", "PLC", "GMBH", "BV", "SAS", "SA", "OPC", "HUF",
    "TRUST", "FOUNDATION", "ASSOCIATION", "INDUSTRIES", "ENTERPRISES", "TRADERS",
    "TECHNOLOGIES", "TECH", "CONSULTANTS", "SERVICES"
}
COMMON_NON_NAME = {
    "INDIA", "BANK", "ACCOUNT", "STATEMENT", "BALANCE", "ADDRESS", "REGISTERED",
    "CERTIFICATE", "INVOICE", "TAX", "ASSESSMENT", "GOVERNMENT"
}
NAME_LABELS = [
    "name", "assessee name", "applicant name", "authorised signatory", "authorized signatory",
    "contact person", "father's name", "fathers name", "guardian name"
]

PTN_INITIALS = re.compile(r"\b(?:[A-Z]\.\s*){1,3}[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){0,2}\b")
PTN_CAPSEQ  = re.compile(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3}\b")
PTN_ALLCAPS = re.compile(r"\b[A-Z]{2,}(?:\s+[A-Z]{1,}\.?)?(?:\s+[A-Z]{2,}){1,3}\b")

def _looks_like_person_name(candidate: str) -> bool:
    toks = [t.strip(".") for t in re.split(r"\s+", candidate.strip()) if t]
    if len(toks) < 2 or len(toks) > 5:
        return False
    if any(t.upper() in COMPANY_TOKENS for t in toks):
        return False
    if any(t.upper() in COMMON_NON_NAME for t in toks):
        return False
    if not any(len(t) > 2 and t.isalpha() for t in toks):
        return False
    return True

def find_person_names_in_text(line_text: str) -> list[tuple[int, int, str]]:
    results = []
    low = line_text.lower()

    # 1) Labelled
    for label in NAME_LABELS:
        idx = low.find(label)
        if idx != -1:
            m = re.search(rf"{re.escape(label)}\s*[:\-–]\s*(.+)$", low[idx:])
            if m:
                start = idx + m.start(1)
                end = idx + m.end(1)
                cand = line_text[start:end].strip()
                cand = re.sub(r"\s*\(.*?\)\s*$", "", cand).strip()
                cand = " ".join(cand.split()[:5])
                if _looks_like_person_name(cand):
                    results.append((start, start + len(cand), cand))

    # 2) Initials + surname
    for m in PTN_INITIALS.finditer(line_text):
        cand = m.group(0).strip()
        if _looks_like_person_name(cand):
            results.append((m.start(), m.end(), cand))

    # 3) Capitalized sequences
    for m in PTN_CAPSEQ.finditer(line_text):
        cand = m.group(0).strip()
        if _looks_like_person_name(cand):
            results.append((m.start(), m.end(), cand))

    # 4) ALL CAPS
    for m in PTN_ALLCAPS.finditer(line_text):
        cand = m.group(0).strip()
        if _looks_like_person_name(cand):
            results.append((m.start(), m.end(), cand))

    # Deduplicate overlaps — keep longest
    results.sort(key=lambda x: (x[0], -(x[1]-x[0])))
    filtered = []
    last_end = -1
    for s, e, t in results:
        if s >= last_end:
            filtered.append((s, e, t))
            last_end = e
    return filtered

# =========================
# Generic ID heuristics
# =========================

def looks_like_date_or_amount(s: str) -> bool:
    s = s.strip()
    if re.match(r"^\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}$", s):
        return True
    if re.match(r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$", s):
        return True
    if re.match(r"^[₹$€]?\s?\d{1,3}(?:[,\s]\d{2,3})*(?:\.\d+)?%?$", s):
        return True
    if re.match(r"^\d+(?:\.\d+)?%$", s):
        return True
    return False

def token_is_probable_id(token: str) -> bool:
    t = token.strip()
    if len(t) < 6 or len(t) > 24:
        return False
    if looks_like_date_or_amount(t):
        return False
    if t.isalpha() and len(t) < 10:
        return False
    if re.fullmatch(r"\d{9,18}", t):
        return True
    if re.fullmatch(r"[A-Za-z0-9\-_/]{6,24}", t) and re.search(r"[A-Za-z]", t) and re.search(r"\d", t):
        return True
    return False

def context_boost(text: str) -> bool:
    low = text.lower()
    return any(kw in low for kw in ID_KEYWORDS)

def match_any(patterns: List[str], text: str) -> List[Tuple[int,int]]:
    """Return list of (start,end) for all regex matches across patterns."""
    hits = []
    for p in patterns:
        for m in re.finditer(p, text, re.IGNORECASE):
            hits.append((m.start(), m.end()))
    return hits

def find_sensitive_value_spans(line_text: str) -> List[Tuple[int,int]]:
    """Targeted spans for PAN/GST/IFSC/Receipt/etc. + keyword:value + generic IDs."""
    spans: List[Tuple[int,int]] = []

    # 1) Direct pattern hits
    spans.extend(match_any(BASE_PATTERNS, line_text))

    # 2) keyword : value   e.g., "Account No: 1234567890", "Rct No- 3666300"
    kw = "|".join(re.escape(k) for k in SENSITIVE_KEYWORDS)
    for m in re.finditer(rf"(?:{kw})\s*(?:no|#|number)?\s*[:\-–]?\s*([A-Z0-9@._\-\/ ]{{5,}})", line_text, re.IGNORECASE):
        start = m.start(1)
        end = m.end(1)
        spans.append((start, end))

    # 3) Generic ID-like tokens (with weak context)
    for m in re.finditer(r"[A-Za-z0-9][A-Za-z0-9\-_\/]{4,}", line_text):
        tok = m.group(0)
        if token_is_probable_id(tok):
            # require some context nearby OR strong alnum mix/ALLCAPS
            window = line_text[max(0, m.start()-25):m.end()+25]
            if context_boost(window) or tok.isupper() or re.search(r"[A-Za-z]{2,}\d{2,}", tok):
                spans.append((m.start(), m.end()))

    # Merge overlapping spans
    if not spans:
        return []
    spans.sort()
    merged = [spans[0]]
    for s,e in spans[1:]:
        ls, le = merged[-1]
        if s <= le:
            merged[-1] = (ls, max(le, e))
        else:
            merged.append((s,e))
    return merged

# =========================
# Redaction helpers
# =========================

def add_blackout(page: "fitz.Page", bbox: Tuple[float, float, float, float]):
    rect = fitz.Rect(bbox)
    page.add_redact_annot(rect, fill=(0, 0, 0))

def apply_all_redactions(doc: "fitz.Document"):
    applied_any = False
    for page in doc:
        try:
            page.apply_redactions()
            applied_any = True
        except Exception:
            pass
    if applied_any:
        return
    try:
        getattr(doc, "apply_redactions")()
        return
    except Exception:
        pass
    for page in doc:
        try:
            annots = page.annots()
            if not annots:
                continue
            for a in annots:
                if a.type[0] == 12:
                    r = a.rect
                    page.draw_rect(r, fill=(0, 0, 0), stroke=None)
        except Exception:
            continue

# =========================
# Main function
# =========================

def redact_pdf_smart(
    input_file: str,
    output_file: Optional[str] = None,
    extra_patterns: Optional[List[str]] = None,
    include_names: bool = True
) -> bool:
    if output_file is None:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_redacted{ext or '.pdf'}"

    patterns = list(BASE_PATTERNS)
    # legacy title-based name patterns (optional)
    name_title_patterns = [
        r"\bMr\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bMs\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bMrs\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bDr\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bShri\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bSmt\.?\s+[A-Z][a-zA-Z\s]{2,30}",
    ]
    if include_names:
        patterns += name_title_patterns

    patterns += load_extra_patterns()
    if extra_patterns:
        patterns += [p for p in extra_patterns if isinstance(p, str)]

    redacted_count = 0
    page_counts = {}

    print(f"[INFO] Input  : {input_file}")
    print(f"[INFO] Output : {output_file}")
    print(f"[INFO] Patterns loaded: {len(patterns)} | Name detection: {include_names}")

    try:
        doc = fitz.open(input_file)
        print(f"[INFO] Opened successfully | Pages: {len(doc)}")

        for page_num in range(len(doc)):
            page = doc[page_num]
            page_hits = 0
            text_dict = page.get_text("dict")
            print(f"[PAGE {page_num + 1}] Scanning...")

            for block in text_dict.get("blocks", []):
                for line in block.get("lines", []):
                    spans = line.get("spans", [])
                    if not spans:
                        continue

                    # Build the full line and char->span map
                    line_text_parts = []
                    span_ranges = []  # [(start_idx, end_idx, bbox, sp_text)]
                    cursor = 0
                    for sp in spans:
                        sp_text = (sp.get("text") or "")
                        if sp_text == "":
                            continue
                        line_text_parts.append(sp_text)
                        start = cursor
                        end = cursor + len(sp_text)
                        span_ranges.append((start, end, sp.get("bbox"), sp_text))
                        cursor = end

                    line_text = "".join(line_text_parts)
                    if not line_text.strip():
                        continue

                    # Find fine-grained sensitive spans
                    sensitive_spans = find_sensitive_value_spans(line_text)

                    # Names within the line
                    name_hits = find_person_names_in_text(line_text) if include_names else []

                    # Combine all spans
                    all_hits = sensitive_spans + [(s, e) for (s, e, _) in name_hits]

                    # If nothing specific matched, no redaction here
                    if not all_hits:
                        continue

                    print(f"  [MATCH] Line : {line_text.strip()!r}")
                    for s, e in sensitive_spans:
                        print(f"    [SENSITIVE] {line_text[s:e]!r}")
                    for s, e, name in name_hits:
                        print(f"    [NAME]      {name!r}")

                    # Compute the line's bounding box to clip searches to this line only
                    line_boxes = [b for (_, _, b, _) in span_ranges if b]
                    if not line_boxes:
                        continue
                    clip_rect = fitz.Rect(
                        min(b[0] for b in line_boxes) - 5,
                        min(b[1] for b in line_boxes) - 2,
                        max(b[2] for b in line_boxes) + 5,
                        max(b[3] for b in line_boxes) + 2,
                    )

                    # Targeted redaction: search for the exact matched text to get its
                    # precise bbox — preserves labels, only blacks out values.
                    for (start_i, end_i) in all_hits:
                        matched_text = line_text[start_i:end_i].strip()
                        if not matched_text or len(matched_text) < 2:
                            continue
                        rects = page.search_for(matched_text, clip=clip_rect)
                        if rects:
                            for rect in rects:
                                add_blackout(page, rect)
                                redacted_count += 1
                                page_hits += 1
                        else:
                            print(f"    [FALLBACK] No rect found for {matched_text!r}, using span bbox")
                            # Fallback: union of intersecting span bboxes
                            boxes = []
                            for sp_start, sp_end, bbox, _ in span_ranges:
                                if bbox and not (sp_end <= start_i or sp_start >= end_i):
                                    boxes.append(bbox)
                            if boxes:
                                x0 = min(b[0] for b in boxes)
                                y0 = min(b[1] for b in boxes)
                                x1 = max(b[2] for b in boxes)
                                y1 = max(b[3] for b in boxes)
                                add_blackout(page, (x0, y0, x1, y1))
                                redacted_count += 1
                                page_hits += 1

            page_counts[page_num + 1] = page_hits
            print(f"[PAGE {page_num + 1}] Redactions applied: {page_hits}")

        print(f"\n[INFO] Applying redactions to document...")
        apply_all_redactions(doc)
        print(f"[INFO] Saving to: {output_file}")
        doc.save(output_file)
        doc.close()
        print(f"\n[DONE] Total redactions: {redacted_count}")
        print(f"[DONE] Per-page summary: {page_counts}")
        print(f"[DONE] Saved: {output_file}")
        return True

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False

# =========================
# Convenience wrappers
# =========================

def quick_redact(filename: str, output_file: Optional[str] = None):
    return redact_pdf_smart(filename, output_file=output_file, include_names=True)

def smart_redact_file(filename: str, output_file: Optional[str] = None, extra_patterns: Optional[List[str]] = None):
    return redact_pdf_smart(filename, output_file=output_file, extra_patterns=extra_patterns, include_names=True)

def test_patterns():
    samples = [
        "Receipt No: 3666300",
        "Rct No 17745808691",
        "Rcpt# 21-ABC-9981",
        "Description: Investment under 80C",  # should NOT redact
        "PAN: ABCDE1234F",
        "Account No: 123456789012",
        "Name: Shivangi Dadheech",
        "PRIYA SHARMA",
    ]
    print("Testing recognizers:")
    for s in samples:
        sens = find_sensitive_value_spans(s)
        names = find_person_names_in_text(s)
        print(f"{s!r} => sensitive_spans={sens} names={names}")

# =========================
# CLI entry point
# =========================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python redact_india.py <file.pdf> [output.pdf]")
        sys.exit(1)

    input_pdf = sys.argv[1]
    output_pdf = sys.argv[2] if len(sys.argv) > 2 else None

    if not input_pdf.lower().endswith(".pdf"):
        print(f"Error: '{input_pdf}' is not a PDF file.")
        sys.exit(1)

    if not os.path.exists(input_pdf):
        print(f"Error: File not found: '{input_pdf}'")
        sys.exit(1)

    success = quick_redact(input_pdf, output_file=output_pdf)
    sys.exit(0 if success else 1)
