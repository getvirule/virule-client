@echo off
rem Builds and runs the evaluation evidence delivery harness (x64, cl), then the
rem sandboxed end-to-end delivery run (tools\evidence_queue_test.mjs).
rem Usage: tests\evidence\run_tests.bat   (from anywhere)
rem Needs no resident client, never touches port 47612 or the real
rem %LOCALAPPDATA%\VIRULE (the helper modes refuse an unredirected profile).
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%ROOT%\build\tests\evidence"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" /I"%ROOT%\third_party\virule_core\include" "%HERE%evidence_tests.cpp" "%ROOT%\third_party\virule_core\time.cpp" /Fo"%OUT%\\" /Fe"%OUT%\evidence_tests.exe" || exit /b 1
"%OUT%\evidence_tests.exe" || exit /b 1
node "%ROOT%\tools\evidence_queue_test.mjs" "%OUT%\evidence_tests.exe"
exit /b %ERRORLEVEL%
