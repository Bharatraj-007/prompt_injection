with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

target4 = """            with tab1:
                st.write("**Cleaned Text:**", res['layer1']['cleaned_text'])
                st.write("**Hidden Chars Detected:**", res['layer1']['has_hidden_chars'])
                if res['layer1']['decoded_base64']:
                    st.warning(f"**Decoded Payloads:** {res['layer1']['decoded_base64']}")
                else:
                    st.info("No encoded/obfuscated payload detected.")"""

replacement4 = """            with tab1:
                l1 = res.get('layer1') or {}
                st.write("**Cleaned Text:**", l1.get('cleaned_text', ''))
                st.write("**Hidden Chars Detected:**", l1.get('has_hidden_chars', False))
                b64_list = l1.get('decoded_base64', [])
                if b64_list:
                    st.warning(f"**Decoded Base64 Payloads:** {b64_list}")
                if l1.get('decoded_hex'):
                    st.warning(f"**Decoded Hex Payloads:** {l1.get('decoded_hex')}")
                if not b64_list and not l1.get('decoded_hex'):
                    st.info("No encoded/obfuscated payload detected.")"""

target5 = """            with tab5:
                st.write("**Generated Dynamic Canary Token:**", f"`{res['layer5']['canary_token']}`")
                st.text_area("Hardened Prompt Sent to LLM:", res['layer5']['hardened_prompt'], height=150)"""

replacement5 = """            with tab5:
                l5 = res.get('layer5')
                if l5:
                    st.write("**Generated Dynamic Canary Token:**", f"`{l5.get('canary_token', 'N/A')}`")
                    st.text_area("Hardened Prompt Sent to LLM:", l5.get('hardened_prompt', ''), height=150)
                else:
                    st.info("Dynamic canary generation skipped.")"""

if target4 not in content and target4.replace('\n', '\r\n') in content:
    target4 = target4.replace('\n', '\r\n')
    replacement4 = replacement4.replace('\n', '\r\n')
if target5 not in content and target5.replace('\n', '\r\n') in content:
    target5 = target5.replace('\n', '\r\n')
    replacement5 = replacement5.replace('\n', '\r\n')

assert target4 in content, "target4 not found"
assert target5 in content, "target5 not found"

content = content.replace(target4, replacement4, 1)
content = content.replace(target5, replacement5, 1)

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Successfully updated tab1 and tab5 in app.py")
