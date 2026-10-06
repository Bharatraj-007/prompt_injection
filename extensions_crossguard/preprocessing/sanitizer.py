import re
import unicodedata
import base64
import torch

class LosslessSanitizerEngine:
    """Layer 1 Sanitizer: NFKC normalization, zero-width space removal, Base64 decoding, character indexing"""
    def __init__(self, max_char_len=256):
        self.max_char_len = max_char_len

    def sanitize(self, text: str) -> dict:
        normalized = unicodedata.normalize('NFKC', text)
        hidden_pattern = re.compile(r'[\u200B-\u200D\uFEFF\u00A0\u200E\u200F\u202A-\u202E]')
        cleaned = hidden_pattern.sub('', normalized)

        # Base64 auto-decoding — capped at 1000 chars to prevent ReDoS
        decoded_payloads = []
        b64_matches = re.findall(r'\b[A-Za-z0-9+/]{12,1000}={0,2}\b', cleaned)
        for b64_str in b64_matches:
            try:
                decoded_bytes = base64.b64decode(b64_str, validate=True)
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
                printable_count = sum(1 for c in decoded if c.isalnum() or c in ' .,!?_-')
                if len(decoded.strip()) >= 5 and (printable_count / len(decoded)) >= 0.8:
                    decoded_payloads.append(decoded)
            except Exception:
                pass

        augmented = cleaned
        if decoded_payloads:
            augmented += " [DECODED_BASE64]: " + " ".join(decoded_payloads)

        # Character indexing (0-255 ASCII)
        char_ids = [min(255, ord(c)) for c in augmented[:self.max_char_len]]
        if len(char_ids) < self.max_char_len:
            char_ids += [0] * (self.max_char_len - len(char_ids))
        
        return {
            "cleaned_text": cleaned,
            "augmented_text": augmented,
            "char_ids": char_ids,
            "has_hidden_chars": len(text) != len(cleaned),
            "decoded_base64": decoded_payloads
        }
