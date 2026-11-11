@echo off
rem Builds and runs the loopback peer identity test (x64, cl):
rem shared\loopback_peer.hpp, the bridge's cross-user refusal (audit H-3).
rem Usage: tests\loopback_peer\run_tests.bat [outdir]
rem Starts NO client and never touches port 47612: every socket is an
rem ephemeral 127.0.0.1 port owned by the test process itself.
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" ( echo vcvars64.bat not found: %VCVARS% & exit /b 1 )
call "%VCVARS%" >nul 2>&1
set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%ROOT%\build\tests\loopback_peer"
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE /I"%ROOT%\src" "%HERE%loopback_peer_tests.cpp" /Fo"%OUT%\\" /Fe"%OUT%\loopback_peer_tests.exe" || exit /b 1
"%OUT%\loopback_peer_tests.exe"
exit /b %ERRORLEVEL%
