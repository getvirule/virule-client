@echo off
rem Builds and runs the usage spool / check-in / update-health harness (x64, cl),
rem then the end-to-end exchange against the real service code.
rem Usage: tests\usage\run_tests.bat   (from anywhere)
rem Needs no resident client and never touches port 47612.
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%ROOT%\build\tests\usage"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" /I"%ROOT%\third_party\virule_core\include" "%HERE%usage_tests.cpp" "%ROOT%\third_party\virule_core\time.cpp" /Fo"%OUT%\\" /Fe"%OUT%\usage_tests.exe" || exit /b 1
"%OUT%\usage_tests.exe" || exit /b 1
node "%ROOT%\tools\usage_checkin_test.mjs" "%OUT%\usage_tests.exe"
exit /b %ERRORLEVEL%
