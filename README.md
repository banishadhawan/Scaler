# PII Redaction Tool (Python 3)

A high-performance, deterministic PII (Personally Identifiable Information) Redaction Tool built in Python. This tool parses Red Herring Prospectus documents in DOCX format, detects sensitive information across 9 different categories, and replaces detected PII with consistent, realistic fake alternatives while preserving the document's formatting.

---

## 1. Project Overview
This repository contains a Python implementation of a PII Redaction Tool designed for processing business reports, prospectuses, and log files. The primary target document is an Indian Red Herring Prospectus. It parses body paragraphs, tables, headers, and footers, and redacts sensitive data using a hybrid approach combining regular expressions, local NLP models, and rule-based validation.

---

## 2. Why Python was Chosen
*   **Powerful NLP Ecosystem:** Python has access to spaCy, an exceptionally fast, industry-standard, and local library for Named Entity Recognition (NER).
*   **Simple & Maintainable XML APIs:** Python's standard library `zipfile` and the third-party `python-docx` library make it extremely straightforward to handle and edit DOCX structures.
*   **Readability:** Python's clear syntax is ideal for presenting code during recruitments and technical interviews.

---

## 3. Architecture
The codebase is structured logically to separate detection, replacement, processing, and evaluation:

```
pii-redaction-tool/
│
├── src/
│   ├── __init__.py
│   ├── redact_pii.py      # Entry point: loads, runs redaction on runs, saves docx
│   ├── detector.py        # Core Engine: matches patterns & runs spaCy NER
│   └── replacer.py        # Mappings: returns consistent fake safe replacements
│
├── evaluation/
│   ├── annotations.json   # Ground-truth annotations
│   ├── evaluate.py        # Alignment metric calculator (character-level)
│   ├── evaluation_report.md
│   └── evaluation_report.csv
│
├── tests/
│   ├── __init__.py
│   └── test_redaction.py  # Unit tests for pytest
│
├── input/
│   └── source_document.docx # Input Red Herring Prospectus
│
├── output/
│   └── redacted_output.docx # Output redacted document
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## 4. PII Detection Approach
The tool uses a **hybrid deterministic and local NLP approach** to cover both structured and unstructured PII types:

### Structured PII
1.  **Email Addresses:** Matched via a precise regular expression matching international standards.
2.  **Phone Numbers:** Matched via an international/Indian pattern supporting prefix digits, country codes, and spaces, validated to contain between 8 and 15 digits.
3.  **SSN / Identity Numbers:** Matches US SSN formats (`XXX-XX-XXXX`) and Indian PAN Cards (`[A-Z]{5}\d{4}[A-Z]`) since this is an Indian prospectus.
4.  **Credit Cards:** Matches digit groups between 13 and 19 characters, validated via length constraints (15/16 digits) and the **Luhn Algorithm** check.
5.  **IP Addresses:** Regex capturing IPv4 and IPv6 addresses (including compressed double-colon syntax).
6.  **Dates of Birth (DOB):** Regexes for multiple date schemas combined with sentence-level context analysis checking for DOB indicators (`birth`, `born`, `dob`, `birthday`, `bday`). This avoids redacting general dates like filing, registration, or table headers.

### Unstructured PII
7.  **Person Names:** Local NER (spaCy `en_core_web_sm` model looking for `PERSON` labels) combined with capitalized word pairs and Mr/Ms title prefix patterns, filtered against stop-words and name exclusions.
8.  **Company/Organization Names:** Local NER (spaCy `ORG` labels) combined with suffix matching patterns (`Ltd`, `Limited`, `LLC`, `Corp`, etc.) and custom brand lists.
9.  **Physical/Mailing Addresses:** Multi-clause address indicators looking for street tags (`Road`, `Rd`, `Street`, `St`, `Lane`, etc.) preceded by numbers/blocks, matching up to 100 character spans.

---

## 5. Replacement Strategy
The `Replacer` guarantees **consistent deterministic mapping**:
*   Predefined pools of obviously synthetic, safe values (e.g., `John Doe`, `ACME Corporation`, `john.doe@example.com`) are selected sequentially.
*   Once a PII value is mapped, it is saved in a hash map (`Map[pii_type:value, fake_replacement]`).
*   If the same PII occurs multiple times throughout the document, it receives the **exact same fake replacement** every time.
*   If the safe value pool is exhausted, the replacer generates dynamic index-numbered fallbacks (e.g. `Fake Company 9 Ltd`).

---

## 6. DOCX Formatting Preservation
Using `python-docx`, the tool parses runs inside paragraphs and cells. When a match spans across multiple runs:
1.  It maps character indexes from the paragraph back to the constituent runs.
2.  It replaces the matched range inside the first run with the fake replacement.
3.  It empties the matched range in any subsequent runs.
This ensures **no styling is lost** (runs retain their bold, italic, or custom font formatting).

---

## 7. Installation & Setup

1.  **Create and activate a virtual environment:**
    ```bash
    python -m venv .venv
    ```
    *   **Windows (PowerShell):**
        ```bash
        .venv\Scripts\activate
        ```
    *   **Mac/Linux:**
        ```bash
        source .venv/bin/activate
        ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Download spaCy Model:**
    ```bash
    python -m spacy download en_core_web_sm
    ```

---

## 8. Usage

### Run Redaction
To redact the prospectus document located at `input/source_document.docx` and write the output to `output/redacted_output.docx`:
```bash
python -m src.redact_pii
```

### Run Evaluation
To run character-level sequence evaluation and output performance metrics:
```bash
python -m evaluation.evaluate
```

### Run Tests
To run unit tests:
```bash
python -m pytest
```

---

## 9. Evaluation Results
The sequence evaluation model aligns character predictions against ground-truth annotations inside the Red Herring Prospectus:

| Metric | Score |
|---|---|
| **Accuracy** | 99.67% |
| **Precision** | 62.36% |
| **Recall** | 79.15% |

### Per-Category Details
- **PERSON:** Precision 88.48% | Recall 89.16%
- **EMAIL:** Precision 100.00% | Recall 98.69%
- **PHONE:** Precision 100.00% | Recall 91.30%
- **COMPANY:** Precision 44.24% | Recall 66.39%
- **ADDRESS:** Precision 27.20% | Recall 100.00%

### Analysis of False Positives & Negatives
*   **False Positives:** Capitalized common words (e.g., "Bank", "Identity") inside headings or legal text are sometimes flagged as ORG by spaCy or regex heuristics. Case mismatches between ground truth annotations ("Kushal...") and document text ("KUSHAL...") are mathematically counted as FPs during sequence evaluation.
*   **False Negatives:** Words like "Central Processing Centre" (expected COMPANY) or names in unstructured layouts (e.g. "Lokesh Shah", "Soumavo Sarkar") can occasionally bypass NER threshold rules.

---

## 10. How to Add a New PII Type

To introduce a new PII type (e.g. `DRIVERS_LICENSE`):

1.  **Define the type:**
    Add the new constant in `src/replacer.py`:
    ```python
    class PiiTypes:
        ...
        DRIVERS_LICENSE = 'DRIVERS_LICENSE'
    ```

2.  **Provide Fake Replacements:**
    Add replacements and initialize tracker inside `Replacer.__init__`:
    ```python
    self.fake_values[PiiTypes.DRIVERS_LICENSE] = ['DL-12345', 'DL-67890']
    self.indices[PiiTypes.DRIVERS_LICENSE] = 0
    ```
    Add dynamic generator fallback in `Replacer.generate_fallback`.

3.  **Add Match Logic in Detector:**
    Add regex pattern to `Detector.__init__`:
    ```python
    self.regexes[PiiTypes.DRIVERS_LICENSE] = re.compile(r'\bDL-[A-Z0-9]{5,10}\b')
    ```
    If custom rules or contextual check is needed, write a validation helper method.
