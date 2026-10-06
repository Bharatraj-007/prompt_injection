"""
Automated Verification Script

Validates that all fixes have been properly applied.
Run this after applying fixes to ensure system integrity.

Usage: python verify_fixes.py
"""
import os
import sys
import importlib
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def check_file_exists(filepath, description):
    """Verify file exists"""
    if os.path.exists(filepath):
        logger.info(f"✅ {description}: {filepath}")
        return True
    else:
        logger.error(f"❌ {description} MISSING: {filepath}")
        return False

def check_imports():
    """Verify all critical imports work"""
    logger.info("\n" + "="*70)
    logger.info("CHECKING IMPORTS")
    logger.info("="*70)
    
    all_pass = True
    
    try:
        import config
        logger.info("✅ config.py imports successfully")
        
        # Check critical attributes exist
        assert hasattr(config, 'MODEL_DIR'), "MODEL_DIR missing"
        assert hasattr(config, 'ID2LABEL'), "ID2LABEL missing (Fix F001)"
        assert hasattr(config, 'LABEL2ID'), "LABEL2ID missing (Fix F001)"
        assert hasattr(config, 'MAX_INPUT_LENGTH'), "MAX_INPUT_LENGTH missing (Fix S003)"
        assert hasattr(config, 'MAX_DECODE_SIZE'), "MAX_DECODE_SIZE missing (Fix S002)"
        logger.info("✅ config.py has all required attributes")
        
    except Exception as e:
        logger.error(f"❌ config.py import failed: {e}")
        all_pass = False
    
    try:
        import guard
        logger.info("✅ guard.py imports successfully")
        
        # Check security fixes
        assert hasattr(guard, 'Layer1Preprocessor'), "Layer1Preprocessor missing"
        assert hasattr(guard, 'Layer4ScoreFusion'), "Layer4ScoreFusion missing"
        logger.info("✅ guard.py has all required classes")
        
    except Exception as e:
        logger.error(f"❌ guard.py import failed: {e}")
        all_pass = False
    
    try:
        import transformers
        version = transformers.__version__
        major = int(version.split('.')[0])
        if major >= 5:
            logger.info(f"✅ transformers version {version} (>=5.0 required)")
        else:
            logger.error(f"❌ transformers version {version} < 5.0 (Fix F013)")
            all_pass = False
    except Exception as e:
        logger.error(f"❌ transformers import failed: {e}")
        all_pass = False
    
    try:
        import Levenshtein
        logger.info("✅ python-Levenshtein installed (Fix F016)")
    except ImportError:
        logger.warning("⚠️  python-Levenshtein not installed (will use fallback)")
    
    return all_pass

def check_files():
    """Verify all required files exist"""
    logger.info("\n" + "="*70)
    logger.info("CHECKING FILES")
    logger.info("="*70)
    
    all_pass = True
    
    # Core files
    files = [
        ("config.py", "Configuration file"),
        ("guard.py", "Defense pipeline"),
        ("train.py", "Training script"),
        ("evaluate.py", "Evaluation script"),
        ("app.py", "Streamlit app"),
        ("data_prep.py", "Data preparation"),
        ("minhash_audit.py", "Contamination audit"),
        ("requirements.txt", "Dependencies"),
        ("requirements-frozen.txt", "Frozen dependencies (Fix R003)"),
        ("environment.yml", "Conda environment (Fix R004)"),
        ("README.md", "Documentation"),
        (".gitignore", "Git exclusions"),
    ]
    
    for filepath, desc in files:
        if not check_file_exists(filepath, desc):
            all_pass = False
    
    # Test files
    test_files = [
        ("tests/test_normalization.py", "Normalization tests"),
        ("tests/test_fusion.py", "Fusion tests (Fix F025)"),
        ("tests/test_rules.py", "Rules tests (Fix F025)"),
    ]
    
    logger.info("\nTest Files:")
    for filepath, desc in test_files:
        if not check_file_exists(filepath, desc):
            all_pass = False
    
    # Documentation files
    doc_files = [
        ("AUDIT_REPORT_PHASE1.md", "Audit report"),
        ("FIXES_APPLIED.md", "Fix tracking"),
        ("FIXES_COMPLETE.md", "Completion report"),
    ]
    
    logger.info("\nDocumentation Files:")
    for filepath, desc in doc_files:
        if not check_file_exists(filepath, desc):
            all_pass = False
    
    # Backup directory
    if os.path.exists("backup"):
        backup_files = os.listdir("backup")
        logger.info(f"✅ Backup directory exists ({len(backup_files)} files)")
    else:
        logger.error("❌ Backup directory missing")
        all_pass = False
    
    return all_pass

def check_code_patterns():
    """Check for specific code patterns that should/shouldn't exist"""
    logger.info("\n" + "="*70)
    logger.info("CHECKING CODE PATTERNS")
    logger.info("="*70)
    
    all_pass = True
    
    # Check guard.py for security fixes
    try:
        with open("guard.py", "r", encoding="utf-8") as f:
            guard_content = f.read()
        
        # Fix S001: Should have bounded regex
        if "{8,10000}" in guard_content:
            logger.info("✅ Fix S001: Base64 regex bounded")
        else:
            logger.error("❌ Fix S001: Base64 regex not bounded")
            all_pass = False
        
        # Fix S002: Should have MAX_DECODE_SIZE check
        if "MAX_DECODE_SIZE" in guard_content:
            logger.info("✅ Fix S002: MAX_DECODE_SIZE check present")
        else:
            logger.error("❌ Fix S002: MAX_DECODE_SIZE check missing")
            all_pass = False
        
        # Fix F012: Should NOT have config import try/except
        if "except ImportError" in guard_content and "from config import" in guard_content:
            # Check if it's after a config import
            lines = guard_content.split('\n')
            has_config_fallback = False
            for i, line in enumerate(lines):
                if 'from config import' in line and i + 5 < len(lines):
                    # Check next few lines for except ImportError
                    context = '\n'.join(lines[i:i+10])
                    if 'except ImportError' in context and 'MODEL_DIR' in context:
                        has_config_fallback = True
                        break
            
            if has_config_fallback:
                logger.error("❌ Fix F012: Config fallback still present in guard.py")
                all_pass = False
            else:
                logger.info("✅ Fix F012: No config fallback in guard.py (Levenshtein fallback is OK)")
        else:
            logger.info("✅ Fix F012: No config fallback in guard.py")
        
    except Exception as e:
        logger.error(f"❌ Could not check guard.py: {e}")
        all_pass = False
    
    # Check train.py for fixes
    try:
        with open("train.py", "r", encoding="utf-8") as f:
            train_content = f.read()
        
        # Fix F014: Should use F1 for best model
        if 'metric_for_best_model="f1"' in train_content:
            logger.info("✅ Fix F014: Best model selected by F1")
        else:
            logger.error("❌ Fix F014: Best model not selected by F1")
            all_pass = False
        
        # Fix R002: Should have deterministic algorithms
        if "use_deterministic_algorithms" in train_content:
            logger.info("✅ Fix R002: Deterministic algorithms enabled")
        else:
            logger.warning("⚠️  Fix R002: Deterministic algorithms not found")
        
    except Exception as e:
        logger.error(f"❌ Could not check train.py: {e}")
        all_pass = False
    
    # Check architecture_diagram.py for fix F030
    try:
        with open("architecture_diagram.py", "r", encoding="utf-8") as f:
            diagram_content = f.read()
        
        # Fix F030: Should have noisy-OR formula
        if "Noisy-OR" in diagram_content or "1 - (1-rule)*(1-model)" in diagram_content:
            logger.info("✅ Fix F030: Architecture diagram shows correct formula")
        else:
            logger.error("❌ Fix F030: Architecture diagram formula not updated")
            all_pass = False
        
    except Exception as e:
        logger.error(f"❌ Could not check architecture_diagram.py: {e}")
        all_pass = False
    
    return all_pass

def check_data_directory():
    """Check data directory structure"""
    logger.info("\n" + "="*70)
    logger.info("CHECKING DATA DIRECTORY")
    logger.info("="*70)
    
    if not os.path.exists("data"):
        logger.error("❌ data/ directory missing")
        return False
    
    expected_files = [
        "train.csv",
        "val.csv",
        "test_seen.csv",
        "test_unseen.csv",
    ]
    
    all_exist = True
    for filename in expected_files:
        filepath = os.path.join("data", filename)
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            logger.info(f"✅ {filename} exists ({size:,} bytes)")
        else:
            logger.warning(f"⚠️  {filename} not yet created (run data_prep.py)")
            all_exist = False
    
    clean_files = ["clean_val.csv", "clean_test_seen.csv", "clean_test_unseen.csv"]
    for filename in clean_files:
        filepath = os.path.join("data", filename)
        if os.path.exists(filepath):
            logger.info(f"✅ {filename} exists (contamination-free)")
        else:
            logger.warning(f"⚠️  {filename} not yet created (run minhash_audit.py)")
    
    return True

def main():
    """Run all verification checks"""
    logger.info("="*70)
    logger.info("AUTOMATED FIX VERIFICATION")
    logger.info("="*70)
    
    results = {
        "Files": check_files(),
        "Imports": check_imports(),
        "Code Patterns": check_code_patterns(),
        "Data Directory": check_data_directory(),
    }
    
    logger.info("\n" + "="*70)
    logger.info("VERIFICATION SUMMARY")
    logger.info("="*70)
    
    all_passed = all(results.values())
    
    for category, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        logger.info(f"{category}: {status}")
    
    logger.info("="*70)
    
    if all_passed:
        logger.info("🎉 ALL VERIFICATIONS PASSED!")
        logger.info("\nNext steps:")
        logger.info("1. Run: python data_prep.py")
        logger.info("2. Run: python minhash_audit.py")
        logger.info("3. Run: python train.py")
        logger.info("4. Run: python evaluate.py")
        logger.info("5. Run: pytest tests/")
        logger.info("6. Run: streamlit run app.py")
        sys.exit(0)
    else:
        logger.error("❌ SOME VERIFICATIONS FAILED!")
        logger.error("\nPlease review the errors above and fix before proceeding.")
        sys.exit(1)

if __name__ == "__main__":
    main()
