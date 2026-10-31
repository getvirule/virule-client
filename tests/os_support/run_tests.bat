@echo off
rem Builds and runs the supported-Windows test (x64, cl): the pure rule and
rem this computer's real version. Usage: tests\os_support\run_tests.bat [outdir]
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%ROOT%\build\tests\os_support"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" "%HERE%os_support_tests.cpp" /Fo"%OUT%\\" /Fe"%OUT%\os_support_tests.exe" || exit /b 1
"%OUT%\os_support_tests.exe"
exit /b %ERRORLEVEL%
