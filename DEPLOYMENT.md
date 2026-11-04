# 🚀 Option 3 (Hybrid Architecture): Hugging Face Model Hub + Streamlit Cloud

This guide provides instructions to run your project using the **Hybrid Architecture**:
- **Model Storage:** Free hosting on **Hugging Face Model Hub** (stores your fine-tuned ~268 MB DistilBERT weights).
- **Web Interface:** Free hosting on **Streamlit Community Cloud** (runs your interactive web UI).
- **Inference:** Streamlit pulls your model from Hugging Face on startup and runs fast cloud LLM evaluations via Groq / Gemini.
- **Cost:** **$0.00 (100% Free Forever)**.

---

```
  +-------------------------------------+
  |   Hugging Face Model Hub            |
  |   (Stores fine-tuned weights ~268MB)|
  +-------------------------------------+
                     |
                     |  (Loaded on App Startup)
                     v
  +-----------------------------------------------------+
  |   Streamlit Community Cloud (https://*.streamlit.app)|
  |   - 7-Layer Hybrid Pipeline                         |
  |   - Multi-View Decoders + Deterministic Rules       |
  |   - LLM-as-a-Judge (Groq / Gemini)                  |
  |   - Guarded Chat + Telemetry Database               |
  +-----------------------------------------------------+
```

---

## 📋 Step 1: Upload Your Model to Hugging Face Hub

Your trained model is located locally at `models/prompt_injection_detector/`. We will upload it to your personal Hugging Face account so Streamlit Cloud can download it on demand.

1. **Get a Hugging Face Write Token:**
   - Log in to [Hugging Face](https://huggingface.co/).
   - Go to [Settings → Access Tokens](https://huggingface.co/settings/tokens).
   - Click **"Create new token"**, select **"Write"** role, and copy it.

2. **Run the included upload utility:**
   In your terminal, execute:
   ```bash
   python upload_model_to_hf.py --repo-id "<your-hf-username>/prompt-injection-distilbert" --token "<your-hf-write-token>"
   ```
   *(Example: `python upload_model_to_hf.py --repo-id "Bharatraj-007/prompt-injection-distilbert" --token "hf_xyz..."`)*

   Once complete, your model will be publicly available at:  
   `https://huggingface.co/<your-hf-username>/prompt-injection-distilbert`

---

## 📋 Step 2: Push Your Project Code to GitHub

Make sure all recent updates are committed and pushed to your GitHub repository:
```bash
git add .
git commit -m "feat: configure hybrid deployment (Hugging Face + Streamlit)"
git push origin main
```

---

## 📋 Step 3: Deploy Frontend on Streamlit Community Cloud

1. Go to **[share.streamlit.io](https://share.streamlit.io/)** and sign in with GitHub.
2. Click **"New app"** and fill in:
   - **Repository:** `Bharatraj-007/prompt_injection`
   - **Branch:** `main`
   - **Main file path:** `app.py`
   - **App URL:** (Optional) Choose a custom URL like `prompt-injection-guard.streamlit.app`

3. **Configure Secrets:**
   Expand **"Advanced settings..." → "Secrets"** and enter:
   ```toml
   # 1. Your Hugging Face model repository from Step 1:
   HF_MODEL_REPO = "<your-hf-username>/prompt-injection-distilbert"

   # 2. Fast cloud LLM Judge & Chat API Keys:
   GROQ_API_KEY = "gsk_..."
   GEMINI_API_KEY = "AIza..."

   # 3. Optional fallback policy if model is still downloading:
   MODEL_FALLBACK_POLICY = "rules_only"
   ```

4. Click **"Deploy!"** 🚀

---

## 🌟 What Happens When Your App Runs?

1. Streamlit Community Cloud launches your app container.
2. Layer 3 automatically reads `HF_MODEL_REPO`, downloads and caches your fine-tuned DistilBERT classifier.
3. The app initializes the complete **7-Layer Hybrid Defense Pipeline**:
   - **Layer 1:** Unicode NFKC normalization, Zero-Width stripping, Spacing collapsed, Leetspeak mapped, Base64/Hex decoded.
   - **Layer 2:** Regex heuristics and adversarial patterns.
   - **Layer 3:** Fine-tuned DistilBERT with sliding-window defense (downloaded from your Hugging Face repo).
   - **Layer 4:** Noisy-OR Multi-Layer Score Fusion.
   - **Layer 5:** Dynamic cryptographic canary tokens.
   - **Layer 6:** Output guard verification.
   - **Layer 7:** High-accuracy semantic LLM as a Judge (via Groq/Gemini).
4. The sidebar will display: `✅ Layer 3 Classifier: Hugging Face Hub (<your-repo-id>)`.

You now have a fast, free, production-grade cloud deployment!
