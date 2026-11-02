@echo off
rem THIS COMPUTER'S READINESS TO BUY AN EVALUATION
rem (src\shared\evaluation_purchase_readiness.hpp): the pure decision over
rem every Windows and antivirus state, the staging test seam, then this
rem computer read for real. No antivirus is changed and no malware file is used.
rem Usage: tests\purchase_readiness\run_tests.bat   (from anywhere)
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%ROOT%\build\tests\purchase_readiness"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /utf-8 /DUNICODE /D_UNICODE /I"%ROOT%\src" /I"%ROOT%\third_party\virule_core\include" "%HERE%purchase_readiness_tests.cpp" /Fo"%OUT%\\" /Fe"%OUT%\purchase_readiness_tests.exe" || exit /b 1
"%OUT%\purchase_readiness_tests.exe"
exit /b %ERRORLEVEL%
