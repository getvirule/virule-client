@echo off
rem Builds and runs the evaluation relay grammar tests (x64, cl).
rem Usage: tests\account_relay\run_tests.bat   (from anywhere)
rem Needs no resident client and never touches port 47612.
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%ROOT%\build\tests\account_relay"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" "%HERE%relay_tests.cpp" /Fo"%OUT%\\" /Fe"%OUT%\relay_tests.exe" || exit /b 1
"%OUT%\relay_tests.exe"
exit /b %ERRORLEVEL%
