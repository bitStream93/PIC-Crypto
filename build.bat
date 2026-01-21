@echo off
set FOLDER=build

if not exist %FOLDER% (
    echo Creating "%FOLDER%" directory...
    mkdir %FOLDER%
)

cd %FOLDER%

echo Running CMake configuration...
cmake -G "MinGW Makefiles" --toolchain="../toolchain-mingw-clang.cmake" ..
cmake --build ../build

pause