@echo off
rem Builds and runs the zip entry name guard test (x64, cl): the Client's two
rem extractors (admin_install extract_package, transfers extract_zip) over
rem the vendored virule/core/zip_entry.hpp (audit L-24).
rem Usage: tests\zip_guard\run_tests.bat [desktop package .zip]
rem The package (default: the staging alpha.77 package the release tests
rem download, %TEMP%\virule-rt\dl\Virule-v0.1.1-alpha.77-staging.zip) is only
rem LISTED: every entry name must pass the guard. Without one, that section
rem is skipped with a note.
rem Starts NO client and never touches port 47612.
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
rem The harness links the malware scanner, so it is built and run OUTSIDE the
rem repository, in a disposable folder that ships nothing (as tests\transfers).
set "OUT=%TEMP%\virule-tests\zip_guard"
if not exist "%OUT%" mkdir "%OUT%"
set "PKG=%~1"
if "%PKG%"=="" if exist "%TEMP%\virule-rt\dl\Virule-v0.1.1-alpha.77-staging.zip" set "PKG=%TEMP%\virule-rt\dl\Virule-v0.1.1-alpha.77-staging.zip"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /I"%ROOT%\src" /I"%ROOT%\third_party" /I"%ROOT%\third_party\virule_core\include" "%HERE%zip_guard_tests.cpp" "%ROOT%\third_party\miniz\miniz.c" "%ROOT%\third_party\virule_core\time.cpp" /Fo"%OUT%\\" /Fe"%OUT%\zip_guard_tests.exe" || exit /b 1
if "%PKG%"=="" ( "%OUT%\zip_guard_tests.exe" ) else ( "%OUT%\zip_guard_tests.exe" "%PKG%" )
exit /b %ERRORLEVEL%
