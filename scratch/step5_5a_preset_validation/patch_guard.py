with open('guard.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = """        if Layer1Preprocessor.is_pure_arithmetic(user_input):
            m_raw = 0.0
            m_norm = 0.0
            m_aug = 0.0
            max_model_score = 0.0
        else:
            m_raw = self.layer3.predict(user_input, rule_score_fallback=0.0)
            m_norm = self.layer3.predict(l1_res["normalized_text"], rule_score_fallback=0.0)
            m_aug = self.layer3.predict(l1_res["augmented_text"], rule_score_fallback=0.0) if l1_res["decoded_payloads"] else 0.0
            max_model_score = max(m_raw, m_norm, m_aug)"""

replacement = """        if Layer1Preprocessor.is_pure_arithmetic(user_input):
            m_raw = 0.0
            m_norm = 0.0
            m_aug = 0.0
            max_model_score = 0.0
        else:
            # Check if input is purely an encoded payload string (Base64/Hex)
            is_pure_b64 = bool(l1_res["decoded_base64"] and re.match(r'^[A-Za-z0-9+/]{12,}={0,2}$', user_input.strip()))
            is_pure_hex = bool(l1_res["decoded_hex"] and re.match(r'^[0-9a-fA-F]{8,}$', user_input.strip()))

            # Explicit inspection of decoded payloads
            m_decoded = 0.0
            if l1_res["decoded_payloads"]:
                for dp in l1_res["decoded_payloads"]:
                    dp_score = self.layer3.predict(dp, rule_score_fallback=0.0)
                    if dp_score > m_decoded:
                        m_decoded = dp_score

            if is_pure_b64 or is_pure_hex:
                # When pure ciphertext is provided, evaluate the decoded semantic payload
                m_raw = m_decoded
                m_norm = m_decoded
                m_aug = m_decoded
                max_model_score = m_decoded
            else:
                m_raw = self.layer3.predict(user_input, rule_score_fallback=0.0)
                m_norm = self.layer3.predict(l1_res["normalized_text"], rule_score_fallback=0.0)
                m_aug = self.layer3.predict(l1_res["augmented_text"], rule_score_fallback=0.0) if l1_res["decoded_payloads"] else 0.0
                max_model_score = max(m_raw, m_norm, m_aug, m_decoded)"""

# Handle both CRLF and LF
if target not in content and target.replace('\n', '\r\n') in content:
    target = target.replace('\n', '\r\n')
    replacement = replacement.replace('\n', '\r\n')

assert target in content, "Target block not found in guard.py"
new_content = content.replace(target, replacement, 1)

with open('guard.py', 'w', encoding='utf-8') as f:
    f.write(new_content)

print("Successfully patched guard.py")
