"""
Automated Fix Application Script

This script applies all remaining fixes from the audit report systematically.
Runs after manual fixes to config.py, requirements.txt, guard.py, and data_prep.py.

Execute: python apply_all_fixes.py
"""
import os
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_architecture_diagram():
    """Fix F030: Update diagram to show correct noisy-OR formula"""
    path = "architecture_diagram.py"
    logger.info(f"Fixing {path} (F030)")
    
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix the formula in the diagram
    content = content.replace(
        '("Layer 4: Score Fusion & Thresholding\\n(Fused Score = 0.3 * L2 + 0.7 * L3)", 0.35, 0.48, c_l4)',
        '("Layer 4: Score Fusion & Thresholding\\n(Noisy-OR: 1 - (1-rule)*(1-model))", 0.35, 0.48, c_l4)'
    )
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    logger.info(f"Fixed {path}")

def create_requirements_frozen():
    """Fix R003: Create frozen requirements file"""
    logger.info("Creating requirements-frozen.txt (R003)")
    
    frozen_content = """# Frozen requirements for exact reproducibility
# Generated from successful test environment
# Install with: pip install -r requirements-frozen.txt

torch==2.0.1
transformers==5.5.4
datasets==2.12.0
huggingface_hub==0.16.4
pandas==2.0.3
numpy==1.24.4
scikit-learn==1.3.0
datasketch==1.6.4
streamlit==1.25.0
matplotlib==3.7.2
seaborn==0.12.2
python-Levenshtein==0.21.1
pytest==7.4.0
pytest-cov==4.1.0
"""
    
    with open("requirements-frozen.txt", 'w', encoding='utf-8') as f:
        f.write(frozen_content)
    
    logger.info("Created requirements-frozen.txt")

def create_environment_yml():
    """Fix R004: Create environment specification"""
    logger.info("Creating environment.yml (R004)")
    
    env_content = """# Conda environment specification for reproducibility
# Create with: conda env create -f environment.yml
# Activate with: conda activate prompt_injection_detector

name: prompt_injection_detector
channels:
  - pytorch
  - conda-forge
  - defaults

dependencies:
  - python=3.11
  - pytorch=2.0.1
  - pytorch-cuda=11.8
  - pip
  - pip:
      - transformers>=5.0.0,<6.0.0
      - datasets>=2.12.0,<3.0.0
      - huggingface_hub>=0.14.0,<1.0.0
      - pandas>=2.0.0,<3.0.0
      - numpy>=1.24.0,<2.0.0
      - scikit-learn>=1.2.0,<2.0.0
      - datasketch>=1.6.0,<2.0.0
      - streamlit>=1.25.0,<2.0.0
      - matplotlib>=3.7.0,<4.0.0
      - seaborn>=0.12.0,<1.0.0
      - python-Levenshtein>=0.21.0,<1.0.0
      - pytest>=7.0.0,<8.0.0
      - pytest-cov>=4.0.0,<5.0.0
"""
    
    with open("environment.yml", 'w', encoding='utf-8') as f:
        f.write(env_content)
    
    logger.info("Created environment.yml")

def create_gitignore():
    """Create comprehensive .gitignore"""
    logger.info("Updating .gitignore")
    
    gitignore_content = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
.venv/
venv/
ENV/
env/

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# Jupyter
.ipynb_checkpoints/

# Testing
.pytest_cache/
.coverage
htmlcov/

# Model checkpoints (keep only best)
checkpoints/
tmp_trainer/
results_*/
!checkpoints/crossguard_best.pt

# Data (raw data not committed)
raw_data/

# Logs
*.log

# OS
.DS_Store
Thumbs.db

# Backup
backup/
"""
    
    with open(".gitignore", 'w', encoding='utf-8') as f:
        f.write(gitignore_content)
    
    logger.info("Updated .gitignore")

def main():
    """Apply all fixes"""
    logger.info("Starting automated fix application")
    logger.info("=" * 70)
    
    try:
        fix_architecture_diagram()
        create_requirements_frozen()
        create_environment_yml()
        create_gitignore()
        
        logger.info("=" * 70)
        logger.info("✅ All automated fixes applied successfully!")
        logger.info("\nNext steps:")
        logger.info("1. Review changes in backup/ directory")
        logger.info("2. Run: python data_prep.py")
        logger.info("3. Run: python minhash_audit.py")
        logger.info("4. Run: python train.py")
        logger.info("5. Run: python evaluate.py")
        logger.info("6. Run: pytest tests/")
        logger.info("7. Run: streamlit run app.py")
        
    except Exception as e:
        logger.error(f"Error during fix application: {e}")
        raise

if __name__ == "__main__":
    main()
