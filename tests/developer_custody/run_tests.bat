@echo off
rem Builds and runs the developer key custody tests (x64, cl).
rem Usage: tests\developer_custody\run_tests.bat   (from anywhere)
rem Needs no resident client, no machine credential and never touches port 47612.
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%ROOT%\build\tests\developer_custody"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" "%HERE%custody_tests.cpp" /Fo"%OUT%\\" /Fe"%OUT%\custody_tests.exe" || exit /b 1
"%OUT%\custody_tests.exe"
exit /b %ERRORLEVEL%
