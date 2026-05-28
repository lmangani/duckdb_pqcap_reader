cmake_minimum_required(VERSION 3.5)

project(pqcap_reader)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(pqcap_reader_extension STATIC
    src/pqcap_reader_extension.cpp
    src/pqcap_footer.cpp
)

target_include_directories(pqcap_reader_extension PRIVATE src)
