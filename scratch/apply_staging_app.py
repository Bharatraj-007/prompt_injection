with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Insert staging banner
old_anchor = "    '</p>',\n    unsafe_allow_html=True,\n)"
new_banner = """    '</p>',
    unsafe_allow_html=True,
)

if LOCAL_STAGING:
    st.markdown(
        '<div style="background-color:#0f2744; border:1px solid #1d4ed8; border-left:6px solid #38bdf8; padding:12px 18px; margin-bottom:16px; border-radius:6px;">'
        '<span style="font-weight:700; color:#93c5fd; font-size:1.0rem;">🛠️ LOCAL STAGING ENVIRONMENT</span><br>'
        '<span style="color:#e0f2fe; font-size:0.88rem;">Safe isolated staging mode active. External AI provider calls are prevented; Mock AI provider is enforced with privacy-safe local telemetry.</span>'
        '</div>',
        unsafe_allow_html=True,
    )"""

if old_anchor in content:
    content = content.replace(old_anchor, new_banner, 1)
    print("Banner inserted (LF)")
else:
    old_anchor_crlf = old_anchor.replace('\n', '\r\n')
    new_banner_crlf = new_banner.replace('\n', '\r\n')
    content = content.replace(old_anchor_crlf, new_banner_crlf, 1)
    print("Banner inserted (CRLF)")

# 2. Update backend_choice in LLM as Judge
old_judge = """backend_choice = st.sidebar.selectbox(
    "LLM Judge Provider",
    options=["Groq Cloud API", "Local GPU (RTX 4050)", "Heuristic Fallback"],
    index=0
)"""

new_judge = """backend_choice = st.sidebar.selectbox(
    "LLM Judge Provider",
    options=["Heuristic Fallback"] if LOCAL_STAGING else ["Groq Cloud API", "Local GPU (RTX 4050)", "Heuristic Fallback"],
    index=0
)"""

if old_judge in content:
    content = content.replace(old_judge, new_judge, 1)
    print("Judge updated (LF)")
else:
    old_judge_crlf = old_judge.replace('\n', '\r\n')
    new_judge_crlf = new_judge.replace('\n', '\r\n')
    content = content.replace(old_judge_crlf, new_judge_crlf, 1)
    print("Judge updated (CRLF)")

# 3. Update chat_provider_choice in Guarded AI Chat
old_chat = """chat_provider_choice = st.sidebar.selectbox(
    "Chat Model Provider",
    options=["Google Gemini", "Groq API", "Local LLM"],
    index=0
)

chat_provider_map = {
    "Google Gemini": "Google Gemini",
    "Groq API": "Groq API",
    "Local LLM": "Local LLM"
}"""

new_chat = """chat_provider_choice = st.sidebar.selectbox(
    "Chat Model Provider",
    options=["Mock AI (Offline Demo)"] if LOCAL_STAGING else ["Google Gemini", "Groq API", "Local LLM"],
    index=0
)

chat_provider_map = {
    "Google Gemini": "Google Gemini",
    "Groq API": "Groq API",
    "Local LLM": "Local LLM",
    "Mock AI (Offline Demo)": "Mock AI (Offline Demo)"
}"""

if old_chat in content:
    content = content.replace(old_chat, new_chat, 1)
    print("Chat updated (LF)")
else:
    old_chat_crlf = old_chat.replace('\n', '\r\n')
    new_chat_crlf = new_chat.replace('\n', '\r\n')
    content = content.replace(old_chat_crlf, new_chat_crlf, 1)
    print("Chat updated (CRLF)")

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("app.py successfully written")
