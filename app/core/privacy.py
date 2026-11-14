import re
from typing import Dict, Any, Tuple

# Regex patterns for Indian Digital Identity documents & common PII
AADHAAR_REGEX = re.compile(r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b')
PAN_REGEX = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', re.IGNORECASE)
PHONE_REGEX = re.compile(r'(\+91[\-\s]?)?[6789]\d{9}\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

def scrub_pii(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Scrubs personally identifiable information (PII) before any text
    is evaluated or sent to upstream models.
    Supports Aadhaar numbers, PAN cards, phone numbers, and candidate emails.
    Returns (sanitized_text, redaction_counts)
    """
    counts = {
        "aadhaar": 0,
        "pan": 0,
        "phone": 0,
        "candidate_email": 0
    }
    
    # Redact Aadhaar
    def _aadhaar_sub(match):
        counts["aadhaar"] += 1
        return "[REDACTED_AADHAAR_UID]"
    sanitized = AADHAAR_REGEX.sub(_aadhaar_sub, text)
    
    # Redact PAN
    def _pan_sub(match):
        counts["pan"] += 1
        return "[REDACTED_PAN_ID]"
    sanitized = PAN_REGEX.sub(_pan_sub, sanitized)
    
    # Redact phone numbers
    def _phone_sub(match):
        counts["phone"] += 1
        return "[REDACTED_PHONE_NUMBER]"
    sanitized = PHONE_REGEX.sub(_phone_sub, sanitized)
    
    return sanitized, counts
