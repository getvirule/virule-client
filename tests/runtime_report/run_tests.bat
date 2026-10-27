@echo off
rem Builds and runs the runtime report harness (x64, cl): the VIRULE Client's
rem runtime report (src\client\runtime_report.hpp) units, then its real
rem signed reports sent to the real service code (tools\runtime_report_test.mjs,
rem ..\..\VIRULE_BACKEND in process).
rem Usage: tests\runtime_report\run_tests.bat   (from anywhere)
rem Needs no resident client, never touches port 47612 or the real
rem %LOCALAPPDATA%\VIRULE (its roots are temporary folders).
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%ROOT%\build\tests\runtime_report"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /MT /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /I"%ROOT%\src" /I"%ROOT%\third_party" /I"%ROOT%\third_party\virule_core\include" "%HERE%runtime_report_tests.cpp" "%ROOT%\third_party\virule_core\time.cpp" /Fo"%OUT%\\" /Fe"%OUT%\runtime_report_tests.exe" || exit /b 1
"%OUT%\runtime_report_tests.exe" || exit /b 1
node "%ROOT%\tools\runtime_report_test.mjs" "%OUT%\runtime_report_tests.exe"
exit /b %ERRORLEVEL%
