class PiiTypes:
    PERSON = 'PERSON'
    EMAIL = 'EMAIL'
    PHONE = 'PHONE'
    COMPANY = 'COMPANY'
    ADDRESS = 'ADDRESS'
    SSN = 'SSN'
    CREDIT_CARD = 'CREDIT_CARD'
    DOB = 'DOB'
    IP_ADDRESS = 'IP_ADDRESS'


class Replacer:
    def __init__(self):
        self.mapping = {}
        
        # Predefined safe replacement values matching the reference project's style
        self.fake_values = {
            PiiTypes.PERSON: [
                'John Doe', 'Jane Smith', 'Peter Parker', 'Bruce Wayne', 'Clark Kent',
                'Diana Prince', 'Tony Stark', 'Steve Rogers', 'Natasha Romanoff',
                'Wanda Maximoff', 'Barry Allen', 'Hal Jordan', 'Arthur Curry'
            ],
            PiiTypes.EMAIL: [
                'john.doe@example.com', 'jane.smith@example.com', 'peter.parker@example.com',
                'bruce.wayne@example.com', 'clark.kent@example.com', 'diana.prince@example.com',
                'tony.stark@example.com', 'steve.rogers@example.com', 'natasha.romanoff@example.com',
                'wanda.maximoff@example.com', 'barry.allen@example.com', 'hal.jordan@example.com'
            ],
            PiiTypes.PHONE: [
                '+91 1234567645', '+91 1234567890', '+91 9876501234', '+91 8765432109',
                '+91 7654321098', '+91 6543210987', '+1 555-0199', '+1 555-0145'
            ],
            PiiTypes.COMPANY: [
                'Example Technologies Pvt Ltd', 'ACME Corporation', 'Globex Corporation',
                'Initech LLC', 'Soylent Corp', 'Umbrella Corp', 'Hooli Inc', 'Veer Industries'
            ],
            PiiTypes.ADDRESS: [
                '123 Example Street, Example City', '456 Sample Road, Testville',
                '789 Mockingbird Lane, Faketown', '101 Placeholder Avenue, Dummy City',
                '202 Fake Street, Noplace', '303 Dummy Lane, Nowhere'
            ],
            PiiTypes.SSN: [
                '000-00-0000', '000-00-0001', '000-00-0002', '000-00-0003',
                '000-00-0004', '000-00-0005', '000-00-0006'
            ],
            PiiTypes.CREDIT_CARD: [
                '4111 1111 1111 1111', '5555 5555 5555 5555', '3777 7777 7777 777',
                '6011 1111 1111 1111', '4222 2222 2222 2222'
            ],
            PiiTypes.DOB: [
                '01/01/1990', '15/05/1985', '23/11/1992', '04/07/1978',
                '12/12/1988', '30/10/1995', '18/02/2000'
            ],
            PiiTypes.IP_ADDRESS: [
                '192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4',
                '198.51.100.1', '198.51.100.2', '203.0.113.1'
            ]
        }

        # Tracks the next index to use for each PII type
        self.indices = {pii_type: 0 for pii_type in self.fake_values}

    def get_replacement(self, text: str, pii_type: str) -> str:
        """
        Returns a consistent fake replacement for the given text and PII type.
        """
        normalized_text = text.strip().lower()
        key = f"{pii_type}:{normalized_text}"

        if key in self.mapping:
            return self.mapping[key]

        list_of_fakes = self.fake_values.get(pii_type, [])
        index = self.indices.get(pii_type, 0)

        if index < len(list_of_fakes):
            fake_val = list_of_fakes[index]
            self.indices[pii_type] = index + 1
        else:
            fake_val = self.generate_fallback(pii_type, index)
            self.indices[pii_type] = index + 1

        self.mapping[key] = fake_val
        return fake_val

    def generate_fallback(self, pii_type: str, index: int) -> str:
        """
        Generates fallback values dynamically when the predefined lists are exhausted.
        """
        suffix = index + 1
        if pii_type == PiiTypes.PERSON:
            return f"Fake Person {suffix}"
        elif pii_type == PiiTypes.EMAIL:
            return f"fake.email{suffix}@example.com"
        elif pii_type == PiiTypes.PHONE:
            return f"+91 999999{suffix:04d}"
        elif pii_type == PiiTypes.COMPANY:
            return f"Fake Company {suffix} Ltd"
        elif pii_type == PiiTypes.ADDRESS:
            return f"{suffix} Fake Road, Faketown"
        elif pii_type == PiiTypes.SSN:
            return f"000-00-{suffix:04d}"
        elif pii_type == PiiTypes.CREDIT_CARD:
            return f"4111 1111 1111 {suffix:04d}"
        elif pii_type == PiiTypes.DOB:
            return "01/01/2000"
        elif pii_type == PiiTypes.IP_ADDRESS:
            return f"192.0.2.{suffix % 255}"
        else:
            return f"Fake Value {suffix}"
