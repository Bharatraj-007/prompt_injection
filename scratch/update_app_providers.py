with open('app.py', 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Ensure typing and pandas imports
if "from typing import Optional" not in code:
    code = code.replace(
        "import logging\nfrom guard import PromptGuardPipeline",
        "import logging\nfrom typing import Optional, Dict, Any, List\nimport pandas as pd\nfrom guard import PromptGuardPipeline"
    )

# 2. Ensure LOCAL_STAGING is imported from config
if "LOCAL_STAGING" not in code.split("from config import")[1].split("from llm_judge")[0]:
    code = code.replace(
        "DEFAULT_GROQ_MODEL, FAST_GROQ_MODEL, DEFAULT_GROK_MODEL",
        "DEFAULT_GROQ_MODEL, FAST_GROQ_MODEL, DEFAULT_GROK_MODEL, LOCAL_STAGING"
    )

# 3. Ensure BenchmarkRunSummary is imported
if "BenchmarkRunSummary" not in code:
    code = code.replace(
        "from redteam_benchmark import RedTeamBenchmark",
        "from redteam_benchmark import RedTeamBenchmark, BenchmarkRunSummary"
    )

# 4. Update LLM Judge Provider selectbox to include Groq, Local GPU, and Fallback
old_judge_pattern = """backend_choice = st.sidebar.selectbox(
    "LLM Judge Provider",
    options=["Heuristic Fallback"] if LOCAL_STAGING else ["Groq Cloud API", "Local GPU (RTX 4050)", "Heuristic Fallback"],
    index=0
)"""
new_judge_code = """judge_options = ["Groq Cloud API", "Local GPU (RTX 4050)", "Heuristic Fallback"]
backend_choice = st.sidebar.selectbox(
    "LLM Judge Provider",
    options=judge_options,
    index=judge_options.index("Heuristic Fallback") if LOCAL_STAGING else 0
)"""
code = code.replace(old_judge_pattern, new_judge_code)

# 5. Update Chat Model Provider selectbox to include Google Gemini, Groq API, Local LLM, and Mock AI
old_chat_pattern = """chat_provider_choice = st.sidebar.selectbox(
    "Chat Model Provider",
    options=["Mock AI (Offline Demo)"] if LOCAL_STAGING else ["Google Gemini", "Groq API", "Local LLM"],
    index=0
)"""
new_chat_code = """chat_provider_options = ["Google Gemini", "Groq API", "Local LLM", "Mock AI (Offline Demo)"]
chat_provider_choice = st.sidebar.selectbox(
    "Chat Model Provider",
    options=chat_provider_options,
    index=chat_provider_options.index("Mock AI (Offline Demo)") if LOCAL_STAGING else 0
)"""
code = code.replace(old_chat_pattern, new_chat_code)

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(code)

print("Updated app.py successfully")
