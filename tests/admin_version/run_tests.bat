@echo off
rem Builds and runs the Desktop update rule test (x64, cl):
rem client\admin_version.hpp (owner ruling 2026-11-13, the operator rollback's
rem withdrawn list). Pure; starts NO client.
rem Usage: tests\admin_version\run_tests.bat [outdir]
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%ROOT%\build\tests\admin_version"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" "%HERE%admin_version_tests.cpp" /Fo"%OUT%\\" /Fe"%OUT%\admin_version_tests.exe" || exit /b 1
"%OUT%\admin_version_tests.exe"
exit /b %ERRORLEVEL%
