@echo off
rem Builds and runs the environment-rule test (x64, cl) TWICE: as a production
rem build (no define) and as a staging build (/DVIRULE_ENV_STAGING), so each
rem rule is proven by the build it belongs to: the local development origins
rem are staging only (shared\environment.hpp, audit M-6), and the development
rem command-line seams are honored only in a staging build or a sandboxed run
rem (shared\dev_seams.hpp, audit L-24), while Setup's own two seams are honored
rem only in a sandboxed run in BOTH builds, with a loopback manifest url.
rem Usage: tests\environment\run_tests.bat [outdir]
rem Starts NO client and never touches port 47612.
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%ROOT%\build\tests\environment"
if not exist "%OUT%\production" mkdir "%OUT%\production"
if not exist "%OUT%\staging" mkdir "%OUT%\staging"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" /I"%ROOT%\third_party\virule_core\include" "%HERE%environment_tests.cpp" /Fo"%OUT%\production\\" /Fe"%OUT%\production\environment_tests.exe" || exit /b 1
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /DVIRULE_ENV_STAGING /I"%ROOT%\src" /I"%ROOT%\third_party\virule_core\include" "%HERE%environment_tests.cpp" /Fo"%OUT%\staging\\" /Fe"%OUT%\staging\environment_tests.exe" || exit /b 1
"%OUT%\production\environment_tests.exe" || exit /b 1
"%OUT%\staging\environment_tests.exe"
exit /b %ERRORLEVEL%
