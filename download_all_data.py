import os
import sys
import subprocess

def download_datasets():
    print("=" * 60)
    print("      PROMPT INJECTION DETECTOR & DEFENDER DATASET DOWNLOADER")
    print("=" * 60)
    
    raw_dir = os.path.join(os.getcwd(), "raw_data")
    os.makedirs(raw_dir, exist_ok=True)
    
    try:
        from datasets import load_dataset
    except ImportError:
        print("[!] Hugging Face `datasets` library not installed. Installing datasets and huggingface_hub...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "datasets", "huggingface_hub", "pandas"], check=True)
        from datasets import load_dataset

    hf_datasets = [
        {"name": "deepset/prompt-injections", "config": None, "folder": "deepset"},
        {"name": "xTRam1/safe-guard-prompt-injection", "config": None, "folder": "xtram1"},
        {"name": "Lakera/gandalf_ignore_instructions", "config": None, "folder": "lakera_ignore"},
        {"name": "Lakera/gandalf_summarization", "config": None, "folder": "lakera_summarization"},
        {"name": "hackaprompt/hackaprompt-dataset", "config": None, "folder": "hackaprompt"},
        {"name": "databricks/databricks-dolly-15k", "config": None, "folder": "dolly"},
        {"name": "neuralchemy/Prompt-injection-dataset", "config": "full", "folder": "neuralchemy"}
    ]

    for ds_info in hf_datasets:
        ds_name = ds_info["name"]
        folder_name = ds_info["folder"]
        save_path = os.path.join(raw_dir, folder_name)
        
        print(f"\n[+] Processing HF Dataset: {ds_name}...")
        try:
            if ds_info["config"]:
                ds = load_dataset(ds_name, ds_info["config"])
            else:
                ds = load_dataset(ds_name)
            
            ds.save_to_disk(save_path)
            print(f"[OK] Successfully downloaded and saved {ds_name} to {save_path}")
        except Exception as e:
            print(f"[X] Failed to download {ds_name}. Reason: {e}")
            print("     Continuing to next dataset...")

    # Clone GitHub Repositories
    github_repos = [
        {"name": "BIPIA (Microsoft)", "url": "https://github.com/microsoft/BIPIA.git", "folder": "BIPIA"},
        {"name": "Prompt Injection (Own Repo)", "url": "https://github.com/Bharatraj-007/prompt_injection.git", "folder": "prompt_injection_repo"}
    ]

    for repo in github_repos:
        repo_path = os.path.join(raw_dir, repo["folder"])
        print(f"\n[+] Cloning GitHub Repository: {repo['name']} ({repo['url']})...")
        if os.path.exists(repo_path):
            print(f"[!] Target directory {repo_path} already exists. Skipping clone.")
            continue
        try:
            result = subprocess.run(["git", "clone", repo["url"], repo_path], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[OK] Successfully cloned {repo['name']} into {repo_path}")
            else:
                print(f"[X] Git clone failed for {repo['name']}. Stderr: {result.stderr.strip()}")
        except Exception as e:
            print(f"[X] Failed to clone {repo['name']}. Reason: {e}")

    print("\n" + "=" * 60)
    print("   DATASET DOWNLOAD & CLONING PROCESS COMPLETED!")
    print(f"   Check your datasets inside: {raw_dir}")
    print("=" * 60)

if __name__ == "__main__":
    download_datasets()
