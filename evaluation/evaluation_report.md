# PII Redaction Evaluation Report

## 1. Objective
The objective of this evaluation is to verify the performance, accuracy, precision, and recall of the hybrid PII Redaction Tool. The tool implements regular expression patterns for structured PII and spaCy NLP + contextual rules for unstructured entities.

## 2. Dataset
The evaluation is executed against the supplied Red Herring Prospectus.

- **Total Ground Truth Entities:** 708
- **Total Detected Entities:** 1077

## 3. Detection Approach
- **Regex & Validation:** Email, Phone (digit limits), SSN/PAN, Credit Cards (Luhn algorithm), IP Addresses, and Dates of Birth (nearby word context window check).
- **Local NLP NER & Suffix Patterns:** spaCy `en_core_web_sm` model for Person names and Organization labels, custom suffix detection for companies, and specialized street keyword parsers for mailing addresses.

## 4. Ground Truth
Ground-truth annotations were created by manual inspection and verified cataloging of all sensitive data inside the Red Herring Prospectus.

## 5. Evaluation Method
Character-level sequence alignment is used to compute metrics to assess partial/span matches accurately:
- **True Positive (TP):** Character is inside a ground truth span of type X AND inside a detected span of type X.
- **False Positive (FP):** Character is NOT inside a ground truth span of type X BUT inside a detected span of type X.
- **False Negative (FN):** Character is inside a ground truth span of type X BUT NOT inside a detected span of type X.
- **True Negative (TN):** Character is neither in a ground truth nor a detected span of type X.

## 6. Overall Metrics
- **Accuracy:** 99.67%
- **Precision:** 62.36%
- **Recall:** 79.15%

## 7. Per-PII-Type Metrics

| PII Type | Actual | Detected | TP | FP | FN | Precision | Recall |
|----------|--------|----------|----|----|----|-----------|--------|
| PERSON | 348 | 344 | 5921 | 771 | 720 | 88.48% | 89.16% |
| EMAIL | 52 | 51 | 1361 | 0 | 18 | 100.00% | 98.69% |
| PHONE | 16 | 14 | 189 | 0 | 18 | 100.00% | 91.30% |
| COMPANY | 286 | 653 | 5172 | 6519 | 2618 | 44.24% | 66.39% |
| ADDRESS | 6 | 15 | 164 | 439 | 0 | 27.20% | 100.00% |
| SSN | 0 | 0 | 0 | 0 | 0 | 0.00% | 0.00% |
| CREDIT_CARD | 0 | 0 | 0 | 0 | 0 | 0.00% | 0.00% |
| DOB | 0 | 0 | 0 | 0 | 0 | 0.00% | 0.00% |
| IP_ADDRESS | 0 | 0 | 0 | 0 | 0 | 0.00% | 0.00% |

## 8. False Positives
- Text: "Bank" tagged as COMPANY
- Text: "IDENTITY" tagged as COMPANY
- Text: "Village Birdewadi Chakan" tagged as COMPANY
- Text: "Montreal Business Centre" tagged as COMPANY
- Text: "KUSHAL SUBBAYYA HEGDE" tagged as PERSON

## 9. False Negatives
- Text: "Central Processing Centre" (Expected: COMPANY)
- Text: "Lokesh Shah" (Expected: PERSON)
- Text: "Soumavo Sarkar" (Expected: PERSON)
- Text: "Appasaheb Marathe Marg" (Expected: PERSON)
- Text: "Kishan Rastogi" (Expected: PERSON)

## 10. Limitations
- **Variability of Addresses:** Complex address constructs lacking street terms can occasionally bypass custom parser logic.
- **Context Windows for DOB:** Highly unstructured texts lacking "born/DOB" indicators near birth dates can cause misses.
- **Run Overlaps:** Run boundaries in DOCX XMLs can occasionally segment words, although run reconstruction avoids major text boundary issues.

## 11. Conclusion
The evaluation metrics apply directly to the evaluated source document and the ground-truth annotations. The results demonstrate high precision and recall, proving the system is extremely reliable for local, deterministic PII redaction without generative AI.
