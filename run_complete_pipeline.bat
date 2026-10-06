@echo off
REM Complete Pipeline Execution Script
REM Runs all steps in the correct order

echo ========================================================================
echo PROMPT INJECTION DETECTION - COMPLETE PIPELINE
echo ========================================================================
echo.

REM Step 0: Set environment variable for deterministic CUDA
echo [Step 0] Setting CUBLAS_WORKSPACE_CONFIG...
set CUBLAS_WORKSPACE_CONFIG=:4096:8
echo           CUBLAS_WORKSPACE_CONFIG=%CUBLAS_WORKSPACE_CONFIG%
echo.

REM Step 1: Verify setup
echo [Step 1] Verifying training setup...
python test_training_setup.py
if %errorlevel% neq 0 (
    echo ERROR: Setup verification failed!
    pause
    exit /b 1
)
echo.

REM Step 2: Prepare data (merge hard negatives)
echo [Step 2] Preparing balanced data with hard negatives...
python data_prep.py
if %errorlevel% neq 0 (
    echo ERROR: Data preparation failed!
    pause
    exit /b 1
)
echo.

REM Step 3: Run contamination audit
echo [Step 3] Running MinHash LSH contamination audit...
python minhash_audit.py
if %errorlevel% neq 0 (
    echo ERROR: MinHash audit failed!
    pause
    exit /b 1
)
echo.

REM Step 4: Train model (3 seeds)
echo [Step 4] Training model across 3 seeds (this will take 15-30 minutes)...
python train.py --model distilbert --epochs 3
if %errorlevel% neq 0 (
    echo ERROR: Training failed!
    pause
    exit /b 1
)
echo.

REM Step 5: Evaluate system
echo [Step 5] Evaluating system and generating plots...
python evaluate.py
if %errorlevel% neq 0 (
    echo ERROR: Evaluation failed!
    pause
    exit /b 1
)
echo.

REM Step 6: Run tests
echo [Step 6] Running test suite...
pytest tests/ -v
if %errorlevel% neq 0 (
    echo ERROR: Tests failed!
    pause
    exit /b 1
)
echo.

echo ========================================================================
echo PIPELINE COMPLETE!
echo ========================================================================
echo.
echo All steps completed successfully. You can now:
echo   1. Review results in plots/ directory
echo   2. Check model in models/prompt_injection_detector/
echo   3. Launch demo: streamlit run app.py
echo.
pause
