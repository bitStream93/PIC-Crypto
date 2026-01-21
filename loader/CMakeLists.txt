cmake_minimum_required(VERSION 3.10)
project(loader_project CXX)

# Define the executable
add_executable(loader loader.cc)

# Link the Windows-specific libraries requested
# These correspond to -ladvapi32 -luser32 -lkernel32
target_link_libraries(loader PRIVATE
        advapi32
        user32
        kernel32
)

# Set the output name to loader.exe
set_target_properties(loader PROPERTIES OUTPUT_NAME "loader")
