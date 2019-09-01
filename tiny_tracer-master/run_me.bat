@echo off
echo PIN is trying to run the app:
echo %1%

set OLDDIR=%CD%

set PIN_DIR=C:\Users\Rustam\Desktop\pin-3.7
set PINTOOL=C:\Users\Rustam\Desktop\pin-3.7\source\tools\tiny_tracer-master\Debug\TinyTracer.dll

rem set TARGET_APP=Pafish.exe
set TARGET_APP=ConsoleApplication1.exe
set ENABLE_SHORT_LOGGING=1

cd %PIN_DIR%
pin.exe -t %PINTOOL% -m %TARGET_APP% -o %TARGET_APP%.tag -s %ENABLE_SHORT_LOGGING% -- %TARGET_APP% 

chdir /d %OLDDIR%