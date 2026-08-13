import pytest
from src.detector import Detector
from src.replacer import Replacer, PiiTypes


def test_email_detection():
    detector = Detector()
    text = "Please reach out to rashi.patil@gmail.com or support@kshinternational.com."
    detections = detector.detect(text)
    emails = [d['text'] for d in detections if d['type'] == PiiTypes.EMAIL]
    assert "rashi.patil@gmail.com" in emails
    assert "support@kshinternational.com" in emails


def test_phone_detection():
    detector = Detector()
    text = "Call me at +91 9876543210 or 020-45053237."
    detections = detector.detect(text)
    phones = [d['text'] for d in detections if d['type'] == PiiTypes.PHONE]
    assert "+91 9876543210" in phones or "9876543210" in phones
    assert "020-45053237" in phones or "45053237" in phones


def test_person_detection():
    detector = Detector()
    # Simple capitalized pattern / titles are fallback options
    text = "The manager is Kushal Subbayya Hegde. Please refer to Mr. Sarthak Malvadkar."
    detections = detector.detect(text)
    people = [d['text'] for d in detections if d['type'] == PiiTypes.PERSON]
    assert "Kushal Subbayya Hegde" in people
    assert "Sarthak Malvadkar" in people


def test_company_detection():
    detector = Detector()
    text = "KSH INTERNATIONAL LIMITED is our company. We also work with Waterloo Motors Private Limited."
    detections = detector.detect(text)
    companies = [d['text'] for d in detections if d['type'] == PiiTypes.COMPANY]
    assert "KSH INTERNATIONAL LIMITED" in companies or "KSH" in companies
    assert "Waterloo Motors Private Limited" in companies


def test_address_detection():
    detector = Detector()
    text = "The registered office is at 201 Montreal Business Centre, Off Pallod Farms, Baner Road, Pune 411 045."
    detections = detector.detect(text)
    addresses = [d['text'] for d in detections if d['type'] == PiiTypes.ADDRESS]
    assert any("Baner Road" in addr for addr in addresses)


def test_ssn_detection():
    detector = Detector()
    # SSN + Indian PAN
    text = "My SSN is 123-45-6789. PAN number is NBWPS1951N."
    detections = detector.detect(text)
    ssns = [d['text'] for d in detections if d['type'] == PiiTypes.SSN]
    assert "123-45-6789" in ssns
    assert "NBWPS1951N" in ssns


def test_credit_card_detection():
    detector = Detector()
    # 4111 1111 1111 1111 passes Luhn
    # 4111 1111 1111 1112 fails Luhn
    text = "Valid card is 4111-1111-1111-1111 and invalid card is 4111-1111-1111-1112."
    detections = detector.detect(text)
    cards = [d['text'] for d in detections if d['type'] == PiiTypes.CREDIT_CARD]
    assert "4111-1111-1111-1111" in cards
    assert "4111-1111-1111-1112" not in cards


def test_dob_detection():
    detector = Detector()
    text = "He was born on December 10, 2025. The document date is Dec 10, 2025."
    detections = detector.detect(text)
    dobs = [d['text'] for d in detections if d['type'] == PiiTypes.DOB]
    assert "December 10, 2025" in dobs
    assert "Dec 10, 2025" not in dobs  # Dec 10 does not have born/birth context near it


def test_ip_detection():
    detector = Detector()
    text = "Log server at 192.0.2.1 and host at 2001:db8::1."
    detections = detector.detect(text)
    ips = [d['text'] for d in detections if d['type'] == PiiTypes.IP_ADDRESS]
    assert "192.0.2.1" in ips
    assert "2001:db8::1" in ips


def test_consistent_replacement():
    replacer = Replacer()
    val1 = replacer.get_replacement("Rashi Patil", PiiTypes.PERSON)
    val2 = replacer.get_replacement("Rashi Patil", PiiTypes.PERSON)
    assert val1 == val2
    assert val1 == "John Doe"

    email1 = replacer.get_replacement("rashi.patil@gmail.com", PiiTypes.EMAIL)
    email2 = replacer.get_replacement("rashi.patil@gmail.com", PiiTypes.EMAIL)
    assert email1 == email2
    assert email1 == "john.doe@example.com"


def test_non_pii_preservation():
    detector = Detector()
    # Regulatory terms, numbers, etc. should not be detected as PII
    text = "Offer of up to 4,200.00 million Equity Shares under SEBI ICDR Regulations."
    detections = detector.detect(text)
    assert len(detections) == 0
