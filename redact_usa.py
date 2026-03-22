import fitz  # PyMuPDF
import re
import json
import os
from typing import List, Optional, Tuple

# =========================
# Config loading
# =========================

def load_extra_patterns(config_path: str = "redact_usa_config.json") -> List[str]:
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
# USA ID patterns
# =========================

BASE_PATTERNS = [
    # Social Security Number (SSN)
    r"\b\d{3}-\d{2}-\d{4}\b",                                      # SSN: 123-45-6789
    r"\b\d{3}\s\d{2}\s\d{4}\b",                                    # SSN spaced: 123 45 6789

    # Employer Identification Number (EIN)
    r"\b\d{2}-\d{7}\b",                                            # EIN: 12-3456789

    # Individual Taxpayer Identification Number (ITIN)
    r"\b9\d{2}-[78]\d-\d{4}\b",                                    # ITIN: 9XX-7X-XXXX or 9XX-8X-XXXX

    # US Passport
    r"\b[A-Z]\d{8}\b",                                             # US Passport: A12345678

    # US Driver's License (common formats)
    r"\b[A-Z]{1,2}\d{6,8}\b",                                      # e.g. A1234567 or AB123456
    r"\b\d{7,9}\b(?=.*(?:license|dl|driver))",                     # numeric DL with context

    # US Phone numbers
    r"\b(?:\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b", # (555) 123-4567 / 555-123-4567 / +1 555 123 4567

    # US ZIP code (5-digit or ZIP+4)
    r"\b\d{5}(?:-\d{4})?\b",                                       # 90210 or 90210-1234

    # Credit/Debit Card numbers (Visa/MC/Amex/Discover)
    r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",            # Visa: 4xxx xxxx xxxx xxxx
    r"\b5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",       # MC: 5xxx xxxx xxxx xxxx
    r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b",                    # Amex: 3xxx xxxxxx xxxxx
    r"\b6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",   # Discover

    # Bank Account / Routing numbers
    r"\b\d{9}\b(?=.*(?:routing|aba|transit))",                     # ABA routing (9 digits with context)
    r"\b\d{8,17}\b(?=.*(?:account|acct|a\/c))",                    # Bank account with context

    # Medicare/Medicaid Beneficiary Identifier (MBI)
    r"\b[1-9][A-Za-z][A-Za-z0-9]\d[A-Za-z][A-Za-z0-9]\d[A-Za-z]{2}\d{2}\b",  # MBI: 1EG4-TE5-MK72

    # National Provider Identifier (NPI) — 10 digit
    r"\b\d{10}\b(?=.*(?:npi|provider))",

    # Email
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",         # Email

    # Date of Birth (common US formats)
    r"\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b",  # MM/DD/YYYY

    # Receipt / Invoice numbers
    r"\b(?:rct|rcpt|receipt|invoice|inv)\s*(?:no|#|number)?\s*[:\-–]?\s*[A-Za-z0-9\-\/]{6,}\b",
]

SENSITIVE_KEYWORDS = [
    "ssn", "social security", "ein", "itin", "taxpayer id",
    "passport", "driver license", "driver's license", "dl number",
    "mobile", "phone", "cell", "telephone", "email",
    "routing", "aba", "account", "a/c", "acct",
    "credit card", "debit card", "card number",
    "medicare", "medicaid", "mbi", "npi",
    "zip", "zip code", "postal",
    "dob", "date of birth", "birthdate",
    "signature", "authorized signatory",
    "customer id", "client id",
    "ref no", "reference no", "invoice", "receipt",
    "license", "licence", "registration", "reg no",
    "member id", "employee id", "emp id",
    "policy", "claim", "folio",
    "green card", "alien", "uscis", "visa number",
]

ID_KEYWORDS = [
    "id", "id no", "id#", "no", "number", "ref", "reference",
    "account", "a/c", "acct", "customer", "client",
    "licence", "license", "dl", "reg", "registration",
    "policy", "folio", "member", "employee", "emp",
    "ssn", "ein", "itin", "npi", "mbi",
    "passport", "routing", "aba",
    "receipt", "rcpt", "rct", "invoice", "inv",
    "zip", "dob",
]

# =========================
# Name detection
# =========================

COMPANY_TOKENS = {
    "INC", "INC.", "LLC", "LLP", "CORP", "CORP.", "CORPORATION",
    "CO", "CO.", "COMPANY", "LTD", "LTD.", "LIMITED",
    "PLC", "LP", "PLLC", "PC", "PA",
    "TRUST", "FOUNDATION", "ASSOCIATION",
    "GROUP", "HOLDINGS", "PARTNERS", "ASSOCIATES",
    "INDUSTRIES", "ENTERPRISES", "SERVICES", "SOLUTIONS",
    "TECHNOLOGIES", "TECH", "CONSULTING", "CONSULTANTS",
}
COMMON_NON_NAME = {
    "USA", "UNITED", "STATES", "AMERICA", "FEDERAL", "STATE",
    "BANK", "ACCOUNT", "STATEMENT", "BALANCE", "ADDRESS",
    "REGISTERED", "CERTIFICATE", "INVOICE", "TAX", "GOVERNMENT",
    "DEPARTMENT", "AGENCY", "BUREAU", "OFFICE", "DIVISION",
}
NAME_LABELS = [
    "name", "full name", "patient name", "applicant name",
    "authorized signatory", "contact person",
    "father's name", "fathers name", "beneficiary name",
    "insured name", "policyholder", "claimant",
    "employee name", "member name",
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

    # 1) Labelled names
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

    # 4) ALL CAPS names
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
    # US date formats: MM/DD/YYYY, MM-DD-YYYY
    if re.match(r"^\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}$", s):
        return True
    if re.match(r"^\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}$", s):
        return True
    # Amounts: $1,234.56 or 1234.56
    if re.match(r"^\$?\s?\d{1,3}(?:[,]\d{3})*(?:\.\d{1,2})?$", s):
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
    # Pure numeric with enough digits
    if re.fullmatch(r"\d{9,18}", t):
        return True
    # Alphanumeric mix (IDs, reference codes)
    if re.fullmatch(r"[A-Za-z0-9\-_/]{6,24}", t) and re.search(r"[A-Za-z]", t) and re.search(r"\d", t):
        return True
    return False

def context_boost(text: str) -> bool:
    low = text.lower()
    return any(kw in low for kw in ID_KEYWORDS)

def match_any(patterns: List[str], text: str) -> List[Tuple[int, int]]:
    hits = []
    for p in patterns:
        for m in re.finditer(p, text, re.IGNORECASE):
            hits.append((m.start(), m.end()))
    return hits

def find_sensitive_value_spans(line_text: str) -> List[Tuple[int, int]]:
    """Targeted spans for SSN/EIN/Phone/Card/etc. + keyword:value + generic IDs."""
    spans: List[Tuple[int, int]] = []

    # 1) Direct pattern hits
    spans.extend(match_any(BASE_PATTERNS, line_text))

    # 2) keyword : value   e.g., "SSN: 123-45-6789", "Account No: 123456789"
    kw = "|".join(re.escape(k) for k in SENSITIVE_KEYWORDS)
    for m in re.finditer(rf"(?:{kw})\s*(?:no|#|number)?\s*[:\-–]?\s*([A-Z0-9@._\-\/ ]{{5,}})", line_text, re.IGNORECASE):
        spans.append((m.start(1), m.end(1)))

    # 3) Generic ID-like tokens (with context)
    for m in re.finditer(r"[A-Za-z0-9][A-Za-z0-9\-_\/]{4,}", line_text):
        tok = m.group(0)
        if token_is_probable_id(tok):
            window = line_text[max(0, m.start()-25):m.end()+25]
            if context_boost(window) or tok.isupper() or re.search(r"[A-Za-z]{2,}\d{2,}", tok):
                spans.append((m.start(), m.end()))

    # Merge overlapping spans
    if not spans:
        return []
    spans.sort()
    merged = [spans[0]]
    for s, e in spans[1:]:
        ls, le = merged[-1]
        if s <= le:
            merged[-1] = (ls, max(le, e))
        else:
            merged.append((s, e))
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
    # Title-based name patterns (US honorifics)
    name_title_patterns = [
        r"\bMr\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bMs\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bMrs\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bDr\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bProf\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bRev\.?\s+[A-Z][a-zA-Z\s]{2,30}",
        r"\bHon\.?\s+[A-Z][a-zA-Z\s]{2,30}",
    ]
    if include_names:
        patterns += name_title_patterns

    patterns += load_extra_patterns()
    if extra_patterns:
        patterns += [p for p in extra_patterns if isinstance(p, str)]

    redacted_count = 0

    try:
        doc = fitz.open(input_file)
        print(f"Opened: {input_file} | Pages: {len(doc)}")

        for page_num in range(len(doc)):
            page = doc[page_num]
            text_dict = page.get_text("dict")

            for block in text_dict.get("blocks", []):
                for line in block.get("lines", []):
                    spans = line.get("spans", [])
                    if not spans:
                        continue

                    # Build the full line and char->span map
                    line_text_parts = []
                    span_ranges = []
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

                    # Find sensitive spans
                    sensitive_spans = find_sensitive_value_spans(line_text)
                    name_hits = find_person_names_in_text(line_text) if include_names else []

                    all_hits = sensitive_spans + [(s, e) for (s, e, _) in name_hits]
                    if not all_hits:
                        continue

                    # If >60% of line is sensitive, wipe the whole line
                    total_sensitive_chars = sum(e - s for (s, e) in all_hits)
                    clean_len = len(line_text.strip())
                    mostly_sensitive = clean_len > 0 and (total_sensitive_chars / clean_len) >= 0.6

                    if mostly_sensitive:
                        boxes = [b for (_, _, b, _) in span_ranges if b]
                        if boxes:
                            x0 = min(b[0] for b in boxes)
                            y0 = min(b[1] for b in boxes)
                            x1 = max(b[2] for b in boxes)
                            y1 = max(b[3] for b in boxes)
                            add_blackout(page, (x0, y0, x1, y1))
                            redacted_count += 1
                        continue

                    # Targeted redaction: only black out matched token regions
                    for (start_i, end_i) in all_hits:
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

        apply_all_redactions(doc)
        doc.save(output_file)
        doc.close()
        print(f"\nTotal items redacted: {redacted_count}")
        print(f"Saved: {output_file}")
        print("SUCCESS")
        return True

    except Exception as e:
        print(f"Error: {e}")
        return False

# =========================
# Convenience wrappers
# =========================

def quick_redact(filename: str, output_file: Optional[str] = None):
    """Redact a PDF with default settings."""
    return redact_pdf_smart(filename, output_file=output_file, include_names=True)

def smart_redact_file(filename: str, output_file: Optional[str] = None, extra_patterns: Optional[List[str]] = None):
    """Redact a PDF with optional extra regex patterns."""
    return redact_pdf_smart(filename, output_file=output_file, extra_patterns=extra_patterns, include_names=True)

def test_patterns():
    """Test the pattern recognizers on sample USA data."""
    samples = [
        "SSN: 123-45-6789",
        "EIN: 12-3456789",
        "Phone: (555) 867-5309",
        "Mobile: +1 800 555 1234",
        "Email: john.doe@example.com",
        "Passport: A12345678",
        "Card: 4111 1111 1111 1111",
        "ZIP: 90210",
        "DOB: 07/04/1985",
        "Name: John Smith",
        "DR. Emily Johnson",
        "Invoice No: INV-2024-00192",
        "Account No: 123456789012",
        "Description: Federal Tax Return",   # should NOT over-redact
        "Amount: $1,234.56",                 # should NOT redact
    ]
    print("Testing USA recognizers:")
    for s in samples:
        sens = find_sensitive_value_spans(s)
        names = find_person_names_in_text(s)
        print(f"  {s!r}")
        print(f"    => sensitive_spans={sens}  names={names}")

# =========================
# Ready message
# =========================

print("USA PDF Redactor Ready!")
print("Functions available:")
print("  quick_redact('filename.pdf')")
print("  smart_redact_file('filename.pdf', extra_patterns=[r'YOUR_REGEX'])")
print("  test_patterns()  # Test pattern recognition on sample data")
print("\nTry: quick_redact('your_document.pdf')")
