@echo off
rem Builds the launcher's live harness (x64, cl): the VIRULE Client's real
rem launcher, transfer driver and evidence delivery in one test process
rem (tests\launcher\launcher_harness.cpp). Driven by
rem ..\..\VIRULE_BACKEND\tools\launcher_lifecycle_staging_e2e.mjs, which runs it
rem in a redirected LOCALAPPDATA against LIVE STAGING.
rem Usage: tests\launcher\build.bat   (from anywhere)
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%ROOT%\build\tests\launcher"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /MT /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /DVIRULE_ENV_STAGING /I"%ROOT%\src" /I"%ROOT%\third_party" /I"%ROOT%\third_party\virule_core\include" "%HERE%launcher_harness.cpp" "%ROOT%\third_party\miniz\miniz.c" "%ROOT%\third_party\virule_core\time.cpp" /Fo"%OUT%\\" /Fe"%OUT%\launcher_harness.exe" || exit /b 1
echo built %OUT%\launcher_harness.exe
exit /b 0
