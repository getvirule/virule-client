@echo off
rem Builds and runs the launch file name test (x64, cl):
rem shared\launch_name.hpp (audit L-25). Pure; starts NO client.
rem Usage: tests\launch_name\run_tests.bat [outdir]
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%ROOT%\build\tests\launch_name"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" "%HERE%launch_name_tests.cpp" /Fo"%OUT%\\" /Fe"%OUT%\launch_name_tests.exe" || exit /b 1
"%OUT%\launch_name_tests.exe"
exit /b %ERRORLEVEL%
