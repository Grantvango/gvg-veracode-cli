@echo off

REM Define the directory to scan
set DIRECTORY_TO_SCAN=path\to\your\directory

REM Run the scan_dir function from main.py
python path\to\your\repo\main.py --scan-dir %DIRECTORY_TO_SCAN%

REM Check the exit status of the scan_dir function
if %ERRORLEVEL% neq 0 (
    echo Scan failed. Aborting push.
    exit /b 1
)

REM If the scan succeeds, allow the push to proceed
exit /b 0