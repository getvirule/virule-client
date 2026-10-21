@echo off
rem Builds and runs the game distribution transfer harness (x64, cl): the
rem client's transfer driver (src\client\transfers.hpp) over the vendored
rem virule/core/evaluation_distribution.hpp, then the sandboxed end-to-end
rem run against a loopback stand-in of the service (tools\transfer_test.mjs).
rem Usage: tests\transfers\run_tests.bat   (from anywhere)
rem Needs no resident client, never touches port 47612 or the real
rem %LOCALAPPDATA%\VIRULE (the helper modes refuse an unredirected profile).
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%ROOT%\build\tests\transfers"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /I"%ROOT%\src" /I"%ROOT%\third_party" /I"%ROOT%\third_party\virule_core\include" "%HERE%transfers_tests.cpp" "%ROOT%\third_party\miniz\miniz.c" /Fo"%OUT%\\" /Fe"%OUT%\transfers_tests.exe" || exit /b 1
"%OUT%\transfers_tests.exe" || exit /b 1
node "%ROOT%\tools\transfer_test.mjs" "%OUT%\transfers_tests.exe"
exit /b %ERRORLEVEL%
