with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

target2 = """        col_btn1, col_btn2 = st.columns([2, 1])
        with col_btn2:
            st.selectbox(
                "Load Attack Sample",
                options=list(SAMPLE_PRESETS.keys()),
                index=0,
                key="sample_selector",
                on_change=on_sample_selected
            )

        user_input = st.text_area(
            "Candidate User Input (Untrusted Prompt)",
            value=st.session_state["user_input_text"],
            height=150,
            max_chars=MAX_INPUT_LENGTH,
            key="main_user_input"
        )
        # Sync typing back to session_state
        st.session_state["user_input_text"] = user_input
        
        if len(user_input) > MAX_INPUT_LENGTH:
            st.warning(f"⚠️ Input exceeds maximum length ({MAX_INPUT_LENGTH} chars). Will be truncated.")
        
        with col_btn1:
            inspect_btn = st.button("🔍 Inspect & Defend", type="primary", use_container_width=True)"""

replacement2 = """        col_btn1, col_btn2 = st.columns([1, 1])
        with col_btn1:
            st.selectbox(
                "Preset Category",
                options=list(PRESET_CATALOG.keys()),
                index=0,
                key="sample_selector",
                on_change=on_sample_selected
            )

        selected_cat = st.session_state.get("sample_selector", "Custom")
        cat_variants = PRESET_CATALOG.get(selected_cat, {})
        with col_btn2:
            if len(cat_variants) > 1:
                st.selectbox(
                    "Test Variant",
                    options=list(cat_variants.keys()),
                    index=0,
                    key=f"sub_variant_{selected_cat}",
                    on_change=on_sample_selected
                )
            else:
                st.markdown('<p style="font-size:0.85rem; color:#888888; margin-top:28px;">Custom Mode: Type untrusted prompt below.</p>', unsafe_allow_html=True)

        user_input = st.text_area(
            "Candidate User Input (Untrusted Prompt)",
            value=st.session_state["user_input_text"],
            height=150,
            max_chars=MAX_INPUT_LENGTH,
            key="main_user_input"
        )
        # Sync typing back to session_state
        st.session_state["user_input_text"] = user_input
        
        if len(user_input) > MAX_INPUT_LENGTH:
            st.warning(f"⚠️ Input exceeds maximum length ({MAX_INPUT_LENGTH} chars). Will be truncated.")
        
        inspect_btn = st.button("🔍 Inspect & Defend", type="primary", use_container_width=True)"""

# Handle CRLF
if target2 not in content and target2.replace('\n', '\r\n') in content:
    target2 = target2.replace('\n', '\r\n')
    replacement2 = replacement2.replace('\n', '\r\n')

assert target2 in content, "target2 not found in app.py"
content = content.replace(target2, replacement2, 1)

target3 = """        # Run pipeline ONLY when Inspect & Defend button is clicked
        if inspect_btn:
            with st.spinner("Analyzing multi-layer defense pipeline..."):
                guard.layer4.threshold = thresh
                st.session_state["pipeline_result"] = guard.inspect_and_defend(
                    user_input, 
                    system_prompt=system_prompt,
                    use_llm_judge=enable_llm_judge
                )"""

replacement3 = """        # Run pipeline ONLY when Inspect & Defend button is clicked
        if inspect_btn:
            if not user_input.strip():
                st.warning("⚠️ Candidate input is empty. Pipeline evaluated with 0.0000 risk score (fail-safe).")
                st.session_state["pipeline_result"] = {
                    "input": "",
                    "decision": "ALLOWED",
                    "is_blocked": False,
                    "risk_score": 0.0,
                    "latency_ms": 0.1,
                    "layer1": {"cleaned_text": "", "has_hidden_chars": False, "decoded_base64": [], "decoded_hex": []},
                    "layer2": {"rule_score": 0.0, "matched_rules": [], "is_flagged": False},
                    "layer3": {"model_score": 0.0},
                    "layer4": {"fused_score": 0.0, "decision": "ALLOWED", "is_blocked": False, "threshold": thresh},
                    "layer5": {"canary_token": "N/A", "hardened_prompt": system_prompt},
                    "layer6": {"status": "ready", "canary_token": "N/A", "leak_detected": False},
                    "layer7": None
                }
            else:
                with st.spinner("Analyzing multi-layer defense pipeline..."):
                    guard.layer4.threshold = thresh
                    st.session_state["pipeline_result"] = guard.inspect_and_defend(
                        user_input, 
                        system_prompt=system_prompt,
                        use_llm_judge=enable_llm_judge
                    )"""

if target3 not in content and target3.replace('\n', '\r\n') in content:
    target3 = target3.replace('\n', '\r\n')
    replacement3 = replacement3.replace('\n', '\r\n')

assert target3 in content, "target3 not found in app.py"
content = content.replace(target3, replacement3, 1)

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Successfully updated tab_inspect in app.py")
