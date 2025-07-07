@echo off
setlocal enabledelayedexpansion

:: Set up Visual Studio environment
set "VSBT_PATH=C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
set "VSBT_PATH_X86=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
set "VCVARS_BAT="

if exist "%VSBT_PATH%\VC\Tools\MSVC" (
    set "VCVARS_BAT=%VSBT_PATH%\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%VSBT_PATH_X86%\VC\Tools\MSVC" (
    set "VCVARS_BAT=%VSBT_PATH_X86%\VC\Auxiliary\Build\vcvars64.bat"
) else (
    echo Error: Visual Studio Build Tools not found!
    pause
    exit /b 1
)

:: Call Visual Studio environment setup first!
call "%VCVARS_BAT%"

:: Set up OpenSSL/vcpkg paths (append, don't overwrite)
set "INCLUDE=%INCLUDE%;C:\Users\ACER\vcpkg\installed\x64-windows\include"
set "LIB=%LIB%;C:\Users\ACER\vcpkg\installed\x64-windows\lib"

:: Compile the program
echo Compiling...
cl c.c /I"C:\Users\ACER\vcpkg\installed\x64-windows\include" /link /LIBPATH:"C:\Users\ACER\vcpkg\installed\x64-windows\lib" libssl.lib libcrypto.lib

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Compilation failed!
    pause
    exit /b 1
)

echo.
echo Compilation successful!
echo.
pause
endlocal