@echo off
rem Builds and runs the binary verification test (x64, cl):
rem shared\verify_binary.hpp, revocation and the exact signer name (audit M-7).
rem Usage: tests\verify_binary\run_tests.bat [outdir]
rem Starts NO client and writes nothing outside outdir. The signed VIRULE
rem executables already in build\Release\x64 (the production build output,
rem signed) are only READ; any that is missing is reported, not built.
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%ROOT%\build\tests\verify_binary"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" "%HERE%verify_binary_tests.cpp" /Fo"%OUT%\\" /Fe"%OUT%\verify_binary_tests.exe" || exit /b 1
set "SIGNED=%ROOT%\build\Release\x64"
"%OUT%\verify_binary_tests.exe" "%SIGNED%\virule-client.exe" "%SIGNED%\ViruleService.exe" "%SIGNED%\Virule-Setup.exe"
exit /b %ERRORLEVEL%
