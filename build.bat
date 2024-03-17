@echo off
if "%PROSPEROGO%" NEQ "" set PATH=%PROSPEROGO%;%PATH%
set GOOS=prospero
ninja clean > nul 2>&1
cd daemon
call go build -o daemon.elf
if ERRORLEVEL 1 (
	cd ..
	EXIT /b 1
)
cd ..
cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_TOOLCHAIN_FILE=%PS5SDK%/cmake/toolchain-ps5.cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 .
if ERRORLEVEL 1 (
	EXIT /b 1
)
ninja
if ERRORLEVEL 1 (
	EXIT /b 1
)
