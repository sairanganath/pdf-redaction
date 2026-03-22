# PDF Redaction Tool

Automatically blackout sensitive personal information in PDF documents.
Two versions are provided:

| File | Region | Covers |
|---|---|---|
| `redact_india.py` | India | PAN, Aadhaar, GSTIN, TAN, IFSC, Indian mobile, PIN code |
| `redact_usa.py` | USA | SSN, EIN, ITIN, Passport, Phone, ZIP, Credit cards, Medicare MBI |

Both versions also redact: **email addresses**, **person names**, **receipt/invoice numbers**, and any **keyword-labelled IDs** (e.g. `Account No: ...`).

---

## How to Run

### 1. Install Python

- Download from https://www.python.org/downloads/
- **Windows:** tick **"Add Python to PATH"** during setup → click Install Now
- **macOS:** open the `.pkg` and follow the installer
- **Linux:** `sudo apt-get install python3 python3-pip`

### 2. Download / Clone this repo

```bash
git clone https://github.com/YOUR_USERNAME/pdf-redaction.git
cd pdf-redaction
```

Or download the ZIP and extract it.

### 3. (Recommended) Create a virtual environment

```bash
# Create
python -m venv .venv

# Activate
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate
```

### 4. Install the required library

```bash
pip install PyMuPDF
```

### 5. Run the script

**USA version:**
```bash
python redact_usa.py
```

Then in the Python IDLE / interactive prompt that opens:
```python
quick_redact("your_document.pdf")
# Output saved as:  your_document_redacted.pdf
```

Or with a custom output path:
```python
smart_redact_file("input.pdf", output_file="output_clean.pdf")
```

**India version:**
```bash
python redact_india.py
```
Then use the same `quick_redact(...)` / `smart_redact_file(...)` calls.

### 6. Run via command line (alternative)

Add this snippet at the bottom of whichever script you want to run from the terminal, then call:

```bash
python redact_usa.py input.pdf output_redacted.pdf
```

---

## What Gets Redacted

### USA (`redact_usa.py`)

| Data Type | Example |
|---|---|
| SSN | `123-45-6789` |
| EIN | `12-3456789` |
| ITIN | `912-77-1234` |
| US Passport | `A12345678` |
| Phone | `(555) 867-5309` / `+1 800 555 1234` |
| Credit/Debit Card | `4111 1111 1111 1111` |
| ZIP code | `90210` / `90210-1234` |
| Date of Birth | `07/04/1985` |
| Email | `john@example.com` |
| Medicare MBI | `1EG4-TE5-MK72` |
| Person names | `John Smith`, `Dr. Emily Johnson` |
| Labelled IDs | `Account No: 123456789` |

### India (`redact_india.py`)

| Data Type | Example |
|---|---|
| PAN | `ABCDE1234F` |
| Aadhaar | `1234 5678 9012` |
| GSTIN | `22ABCDE1234F1Z5` |
| TAN | `ABCD12345E` |
| IFSC | `SBIN0001234` |
| Indian Mobile | `9876543210` / `+91 98765 43210` |
| PIN Code | `400001` |
| Email | `user@domain.com` |
| Person names | `Mr. Rahul Sharma`, `PRIYA SHARMA` |
| Receipt | `Rct No: 3666300` |

---

## Add Custom Patterns

Create a `redact_usa_config.json` (or `redact_config.json` for India) next to the script:

```json
{
  "extra_patterns": [
    "\\bEMP-\\d{6}\\b",
    "\\bPOL-[A-Z]{2}\\d{8}\\b"
  ]
}
```

These regex patterns will be applied in addition to the built-in ones.

---

## Test the Patterns

```python
# Run inside Python / IDLE after loading the script
test_patterns()
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `python not recognized` | Reopen terminal; ensure "Add Python to PATH" was ticked during install |
| `ModuleNotFoundError: fitz` | Run `pip install PyMuPDF` inside your activated venv |
| Permission error on macOS | Right-click installer → Open |
| Output PDF looks unchanged | Ensure the PDF has selectable text (not a scanned image) |

---

