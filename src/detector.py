import re
import spacy
from typing import List, Dict, Any
from .replacer import PiiTypes


def luhn_check(num_str: str) -> bool:
    """
    Luhn Algorithm check to validate credit card numbers.
    """
    num = re.sub(r'\D', '', num_str)
    if not (13 <= len(num) <= 19):
        return False
    
    total = 0
    should_double = False
    for i in range(len(num) - 1, -1, -1):
        digit = int(num[i])
        if should_double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        should_double = not should_double
    return total % 10 == 0


def merge_overlapping_spans(spans: List[Dict[str, Any]], text: str) -> List[Dict[str, Any]]:
    """
    Sorts and merges overlapping detected entities.
    """
    if not spans:
        return []
    
    # Sort spans by start index, then by length descending
    spans.sort(key=lambda s: (s['start'], -(s['end'] - s['start'])))
    
    merged = []
    for current in spans:
        if not merged:
            merged.append(current)
            continue
        last = merged[-1]
        if current['start'] < last['end']:
            # Overlap detected. Keep the larger span.
            if current['end'] > last['end']:
                last['end'] = current['end']
                last['text'] = text[last['start']:last['end']]
        else:
            merged.append(current)
    return merged


class Detector:
    def __init__(self):
        # Attempt to load spaCy's small English model
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            try:
                from spacy.cli import download
                download("en_core_web_sm")
                self.nlp = spacy.load("en_core_web_sm")
            except Exception:
                self.nlp = None

        # Regex definitions for structured PII
        self.regexes = {
            PiiTypes.EMAIL: re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE),
            
            # Matches international and Indian/local phone numbers
            PiiTypes.PHONE: re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b'),
            
            # Matches US SSN and Indian PAN Card numbers
            PiiTypes.SSN: re.compile(r'\b\d{3}-\d{2}-\d{4}\b|\b[A-Z]{5}\d{4}[A-Z]\b'),
            
            # Matches potential credit cards (to be checked by Luhn)
            PiiTypes.CREDIT_CARD: re.compile(r'\b(?:\d[ -]*?){13,19}\b'),
            
            # IPv4 and IPv6 (including compressed double-colon IPv6)
            PiiTypes.IP_ADDRESS: re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
                r'\b::(?:[0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
            )
        }

        # Date regexes for Date of Birth checking
        self.date_regexes = [
            re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b'),
            re.compile(r'\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b'),
            re.compile(r'\b\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*,?\s*\d{4}\b', re.IGNORECASE),
            re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?\s*,?\s*\d{4}\b', re.IGNORECASE)
        ]

        # Stop words to prevent over-redacting common ticket/system/prospectus terms
        self.stop_words = {
            'ticket', 'order', 'product', 'employee', 'manager', 'admin', 'user', 'server', 'client',
            'hostname', 'database', 'port', 'id', 'version', 'status', 'error', 'debug', 'info',
            'warning', 'exception', 'file', 'folder', 'path', 'system', 'network', 'application',
            'comment', 'details', 'log', 'event', 'incident', 'issue', 'request', 'subject', 'date',
            'time', 'timestamp', 'created', 'updated', 'history', 'notes', 'attachment', 'priority',
            'sebi', 'upi', 'asba', 'brlms', 'scsb', 'scsbs', 'company', 'promoter', 'group', 'board',
            'directors', 'exchange', 'exchanges', 'stock', 'shares', 'equity', 'prospectus', 'act',
            'rules', 'regulations', 'india', 'government', 'state', 'registrar', 'auditors', 'committee',
            'particulars', 'amount', 'fiscal', 'year', 'march', 'june', 'december', 'offer', 'price',
            'fresh', 'issue', 'sale', 'total', 'eligible', 'eligibility', 'public', 'initial', 'capital',
            'structure', 'history', 'objects', 'proceeds', 'general', 'risks', 'responsibility',
            'audit', 'financial', 'statement', 'statements', 'report', 'reports', 'pan', 'tan', 'din',
            'cin', 'net', 'worth', 'revenue', 'profit', 'earnings', 'basic', 'diluted', 'asset', 'assets',
            'borrowings', 'liabilities', 'litigation', 'contingent', 'related', 'party', 'transactions'
        }

        # Words to exclude from Person names
        self.excluded_name_words = {
            'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday',
            'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December',
            'Jan', 'Feb', 'Mar', 'Apr', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
            'The', 'This', 'That', 'These', 'Those', 'There', 'Their', 'Here', 'What', 'When', 'Where', 'Who', 'Which', 'Why', 'How',
            'If', 'Then', 'Else', 'And', 'But', 'Or', 'Not', 'Yes', 'No', 'Ok', 'Okay', 'Dear', 'Hello', 'Hi', 'Hey', 'Greetings',
            'Sincerely', 'Regards', 'Thanks', 'Thank', 'Please', 'Kindly', 'Attention', 'Subject', 'Date', 'Time', 'Log', 'Status',
            'Ltd', 'Limited', 'Inc', 'Incorporated', 'Corp', 'Corporation', 'Co', 'Company', 'Technologies', 'Solutions', 'Group', 'Services', 'Enterprises', 'LLC', 'LLP', 'Pvt',
            'Red', 'Herring', 'Prospectus', 'Equity', 'Shares', 'Offer', 'Price', 'Sale', 'BRLMs', 'Registrar', 'Auditors', 'Independent', 'Director', 'Executive',
            'Facility', 'Mutual', 'Funds', 'Business', 'Portion', 'Personnel', 'Pension', 'Book', 'Running', 'Lead', 'Managers', 'Contact', 'Person', 'Bidders', 'Bids', 'Anchor', 'Investors', 'Institutional', 'Statutory',
            'Pune', 'Mumbai', 'Maharashtra', 'India', 'Chakan', 'Khed', 'Birdewadi', 'Baner', 'Taloja', 'Vikhroli', 'Thane', 'Prabhadevi', 'Kothrud', 'Bhopal', 'Madhya', 'Pradesh', 'Gujarat', 'UAE', 'Ahmednagar', 'Ahilyanagar', 'Supa', 'Khalumbre', 'Panvel', 'Raigad', 'Shivaji', 'Nagar', 'Model', 'Colony', 'Erandawane', 'Deccan', 'Gymkhana', 'Pashan', 'Panchvati', 'Karve', 'Road', 'Bungalow', 'Chowk', 'Sterling', 'Embassy', 'Inspire', 'BKC', 'Bandra', 'Kurla', 'Complex', 'Kanjurmarg', 'Churchgate', 'Reclamation', 'Koregaon', 'Cantonment', 'Wakdewadi', 'Tara', 'Chambers', 'Gat', 'Plot', 'No', 'Sr', 'DIN', 'CIN', 'PAN', 'TAN', 'DSC', 'ITR', 'TDS', 'GST', 'VAT', 'CST', 'BSE', 'NSE', 'SEBI', 'ICDR', 'Regulations', 'Annexure', 'Particulars', 'Total', 'Amount', 'Fiscal', 'Year', 'March', 'June', 'December', 'September', 'October', 'November', 'January', 'February', 'April', 'May', 'July', 'August', 'Refund', 'Bank', 'Branches', 'Branch', 'Syndicate', 'Village', 'Taluka', 'Compliance', 'Officer', 'Email', 'Telephone', 'Tel', 'Website', 'Web', 'Period', 'Closing', 'Opening', 'Draft', 'RHP', 'DRHP', 'Face', 'Value', 'Fresh', 'Issue', 'Sale', 'Size', 'Eligible', 'Eligibility', 'Reservation', 'Promoter', 'Promoters', 'Selling', 'Shareholder', 'Shareholders', 'Audit', 'Committee', 'Board', 'Directors', 'Management', 'Materiality', 'Policy', 'Abridged', 'Acknowledgement', 'Slip', 'Allot', 'Allotment', 'Allotted', 'Advice', 'Alloftee', 'Escrow', 'Collection', 'Sponsor', 'Agreement', 'Member', 'Members', 'Underwriters', 'Underwriting', 'Interface', 'Payments', 'Unified', 'Mobile', 'Mandate', 'Request', 'Mechanism', 'PIN', 'Wilful', 'Defaulter', 'Working', 'Day', 'Days', 'Alternate', 'Investment', 'Fund', 'Assessment', 'Category', 'Growth', 'Rate', 'Depository', 'Customs', 'Excise', 'Appellate', 'Tribunal', 'Companies', 'Act', 'Corporate', 'Social', 'Responsibility', 'Participant', 'Promotion', 'Industry', 'Internal', 'Trade', 'Ministry', 'Commerce', 'Earnings', 'Before', 'Interest', 'Taxes', 'Depreciation', 'Amortization', 'Factories', 'Foreign', 'Exchange', 'Finance', 'Bill', 'Portfolio', 'Government', 'Goods', 'Hindu', 'Undivided', 'Family', 'Trust', 'Automotive', 'Task', 'Force', 'Income', 'Tax', 'Institute', 'Accounting', 'Standards', 'Generally', 'Accepted', 'Principles', 'Public', 'Organization', 'Standard', 'Information', 'Technology', 'Legal', 'Entity', 'Identifier', 'Marginal', 'Cost', 'Metric', 'Ton', 'Automated', 'Clearing', 'House', 'Electronic', 'Transfer', 'External', 'Account', 'Ordinary', 'Securities', 'Complaints', 'Redressal', 'Self', 'Certified', 'Agent', 'Transaction', 'Underwriter', 'Systemically', 'Important', 'Format', 'Sample', 'Project', 'Report', 'Syllabus', 'Course', 'Master', 'Cheatsheet', 'Complete', 'DevOps', 'Docker', 'Jenkins', 'Maven', 'Git', 'GitHub', 'Visual', 'Studio', 'Code', 'Webex', 'WPS', 'Office', 'PDF', 'XML', 'HTML', 'JavaScript', 'Node', 'React', 'Next', 'Vite', 'Tailwind', 'CSS', 'Snyk', 'Socket', 'Dependabot', 'Luhn', 'Algorithm', 'Precision', 'Recall', 'Accuracy', 'F1', 'TP', 'FP', 'FN', 'TN', 'PAN', 'TAN', 'DIN', 'CIN', 'DSC', 'ITR', 'TDS', 'GST', 'VAT', 'CST', 'Service', 'Property', 'Stamp', 'Registration', 'Charges', 'Dividend', 'Distribution', 'Wealth', 'Gift', 'Capital', 'Gains', 'Levy', 'Corporate', 'Minimum', 'Fringe', 'Benefit', 'Provident', 'Superannuation', 'Bonus', 'Commission', 'Allowance', 'Perquisite', 'Salary', 'Wages', 'Remuneration', 'Sitting', 'Fee', 'Fees', 'Nomination', 'Relationship', 'CSR', 'Risk', 'Independent', 'Non-Executive', 'Executive', 'Managing', 'Whole-time', 'Manager', 'CEO', 'CFO', 'Cost', 'Secretarial', 'Internal', 'Tax', 'Transfer', 'Pricing', 'Chartered', 'Engineers', 'Architects', 'Actuaries', 'Brokers', 'Merchant', 'Bankers', 'Investment', 'Sponsor', 'Escrow', 'Refund', 'Public', 'Adsorptive', 'Advertising', 'Agencies', 'PR', 'Media', 'Printing', 'Dispatch', 'Courier', 'Logistics', 'Transport', 'Travel', 'Hotel', 'Catering', 'Security', 'Housekeeping', 'Maintenance', 'Utility', 'Reinsurance', 'Actuarial', 'Brokerage', 'Valuation', 'Engineering', 'Consulting', 'Advisory', 'Research', 'Rating', 'Verification', 'Due', 'Diligence', 'Legal', 'Customs', 'RoC', 'Central', 'Municipal', 'Panchayat', 'District', 'Ward', 'Zonal', 'Regional', 'National', 'International', 'Global', 'Offshore', 'Onshore', 'Inshore', 'Outshore', 'Nearshore', 'Co-operative', 'Collective', 'Collaborative', 'Consortium', 'Joint', 'Venture', 'Partnership', 'Proprietorship', 'Association', 'Federation', 'Chamber', 'Council', 'Commission', 'Authority', 'Firm', 'Enterprise', 'Commercial', 'Trading', 'Manufacturing', 'Scientific', 'Educational', 'Medical', 'Healthcare', 'Cultural', 'Religious', 'Charitable', 'Non-profit', 'NGO', 'Civil', 'Political', 'Defense', 'Intelligence', 'Police', 'Judicial', 'Legislative', 'Administrative', 'Regulatory', 'Supervisory', 'Enforcement', 'Investigating', 'Prosecuting', 'Defending', 'arbitration', 'Mediation', 'Conciliation', 'Settlement', 'Resolution'
        }

        # Suffix-based Company names regex
        self.company_suffix_pattern = re.compile(
            r"\b[A-Z][A-Za-z0-9&']*(?:\s+[A-Z][A-Za-z0-9&']*)*\s+"
            r"(?:Pvt\s+Ltd|Private\s+Limited|Ltd|Limited|Inc|Incorporated|LLC|Corp|Corporation|Co|Company|"
            r"Technologies|Solutions|Group|Services|Enterprises|PVT\s+LTD|PRIVATE\s+LIMITED|LTD|LIMITED|"
            r"INC|INCORPORATED|CORP|CORPORATION|CO|COMPANY|TECHNOLOGIES|SOLUTIONS|GROUP|SERVICES|ENTERPRISES)"
            r"(?:\s+(?:Pvt\s+Ltd|Private\s+Limited|Ltd|Limited|Inc|Incorporated|LLC|Corp|Corporation|Co|Company|"
            r"Technologies|Solutions|Group|Services|Enterprises|PVT\s+LTD|PRIVATE\s+LIMITED|LTD|LIMITED|"
            r"INC|INCORPORATED|CORP|CORPORATION|CO|COMPANY|TECHNOLOGIES|SOLUTIONS|GROUP|SERVICES|ENTERPRISES))*\b"
        )

        # Brand and domain custom company patterns
        self.custom_company_pattern = re.compile(r'\bKSH\b|\bkshinternational\b', re.IGNORECASE)

        # Address indicator patterns (allow longer spans between block numbers and street suffixes)
        self.address_pattern = re.compile(
            r'\b\d{1,5}\s+[A-Z][A-Za-z0-9\s#,\.\-]{1,100}\s+'
            r'(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct|Way|Plaza|Plz|Terrace|Ter|'
            r'Parkway|Pkwy|Circle|Cir|Apartment|Apt|Suite|Ste|Floor|Fl)\b(?:[A-Za-z0-9\s,\.\-#]*\b\d{5,6}\b)?',
            re.IGNORECASE
        )

        # Name fallback regexes
        self.name_pair_pattern = re.compile(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b')
        self.name_prefix_pattern = re.compile(r'(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)')

    def contains_stop_word(self, text: str) -> bool:
        """
        Tokenizes text and checks if it contains stop words.
        """
        tokens = re.findall(r'[a-zA-Z0-9]+', text.lower())
        return any(t in self.stop_words for t in tokens)

    def is_valid_name(self, name: str) -> bool:
        """
        Validates whether a matched string is a valid Person name.
        """
        words = name.strip().split()
        if len(words) < 2:
            return False
        
        # Check exclusions
        if any(w in self.excluded_name_words or w.lower() in self.stop_words for w in words):
            return False

        # Ensure all words start with uppercase
        if not all(bool(re.match(r'^[A-Z][A-Za-z]+$', w)) for w in words):
            return False

        return True

    def is_date_of_birth(self, date_str: str, index: int, full_text: str) -> bool:
        """
        Looks at context surrounding the matched date to identify if it is a Date of Birth.
        """
        # Find sentence boundaries
        sentence_start = full_text.rfind('.', 0, index)
        if sentence_start == -1 or (index - sentence_start > 50):
            sentence_start = max(0, index - 35)
        else:
            sentence_start += 1
            
        sentence_end = full_text.find('.', index)
        if sentence_end == -1 or (sentence_end - index > 35):
            sentence_end = min(len(full_text), index + len(date_str) + 15)
            
        surrounding = full_text[sentence_start:sentence_end].lower()
        
        dob_indicators = ['dob', 'birth', 'born', 'd.o.b', 'bday', 'birthday']
        return any(ind in surrounding for ind in dob_indicators)

    def detect(self, text: str) -> List[Dict[str, Any]]:
        """
        Detects PII from a plain text block and returns span records.
        """
        if not text:
            return []
        
        findings = []

        # --- 1. Regex Detection for Structured PII ---
        for pii_type, regex in self.regexes.items():
            for match in regex.finditer(text):
                matched_text = match.group(0)
                start = match.start()
                end = match.end()

                if pii_type == PiiTypes.PHONE:
                    digits = re.sub(r'\D', '', matched_text)
                    if not (8 <= len(digits) <= 15):
                        continue

                if pii_type == PiiTypes.CREDIT_CARD:
                    digits = re.sub(r'\D', '', matched_text)
                    if len(digits) not in (15, 16):
                        continue
                    if not luhn_check(matched_text):
                        continue

                findings.append({
                    'text': matched_text,
                    'type': pii_type,
                    'start': start,
                    'end': end
                })

        # --- 2. Custom Date of Birth Detector ---
        for d_regex in self.date_regexes:
            for match in d_regex.finditer(text):
                matched_text = match.group(0)
                start = match.start()
                end = match.end()

                if self.is_date_of_birth(matched_text, start, text):
                    findings.append({
                        'text': matched_text,
                        'type': PiiTypes.DOB,
                        'start': start,
                        'end': end
                    })

        # --- 3. NLP NER (spaCy) and fallback rules ---
        if self.nlp:
            doc = self.nlp(text)
            for ent in doc.ents:
                # Name entities
                if ent.label_ == "PERSON":
                    name = ent.text.strip()
                    if len(name) >= 3 and not self.contains_stop_word(name) and self.is_valid_name(name):
                        findings.append({
                            'text': name,
                            'type': PiiTypes.PERSON,
                            'start': ent.start_char,
                            'end': ent.end_char
                        })
                # Company entities
                elif ent.label_ in ("ORG", "COMPANY"):
                    org = ent.text.strip()
                    if len(org) >= 3 and not self.contains_stop_word(org):
                        findings.append({
                            'text': org,
                            'type': PiiTypes.COMPANY,
                            'start': ent.start_char,
                            'end': ent.end_char
                        })

        # Fallback Capitalized Word Pairs for Person names (handles NER misses)
        for match in self.name_pair_pattern.finditer(text):
            name = match.group(0)
            start = match.start()
            end = match.end()
            if self.is_valid_name(name):
                findings.append({
                    'text': name,
                    'type': PiiTypes.PERSON,
                    'start': start,
                    'end': end
                })

        # Fallback Title Prefixes for Person names
        for match in self.name_prefix_pattern.finditer(text):
            name = match.group(1)
            start = match.start() + match.group(0).index(name)
            end = start + len(name)
            if not self.contains_stop_word(name) and self.is_valid_name(name):
                findings.append({
                    'text': name,
                    'type': PiiTypes.PERSON,
                    'start': start,
                    'end': end
                })

        # Fallback Suffix-based Company Names
        for match in self.company_suffix_pattern.finditer(text):
            matched_text = match.group(0)
            start = match.start()
            end = match.end()
            if not self.contains_stop_word(matched_text):
                findings.append({
                    'text': matched_text,
                    'type': PiiTypes.COMPANY,
                    'start': start,
                    'end': end
                })

        # Fallback Custom Company names list (e.g. KSH)
        for match in self.custom_company_pattern.finditer(text):
            matched_text = match.group(0)
            start = match.start()
            end = match.end()
            findings.append({
                'text': matched_text,
                'type': PiiTypes.COMPANY,
                'start': start,
                'end': end
            })

        # Fallback Physical Addresses
        for match in self.address_pattern.finditer(text):
            matched_text = match.group(0)
            start = match.start()
            end = match.end()
            findings.append({
                'text': matched_text,
                'type': PiiTypes.ADDRESS,
                'start': start,
                'end': end
            })

        # Merge overlapping/redundant spans and return cleanly
        return merge_overlapping_spans(findings, text)
