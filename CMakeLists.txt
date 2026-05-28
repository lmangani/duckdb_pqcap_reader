cmake_minimum_required(VERSION 3.5)

set(TARGET_NAME pqcap_reader)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include src)

set(LIGHT_PCAPNG_SOURCES
    third_party/LightPcapNg/src/light_advanced.c
    third_party/LightPcapNg/src/light_alloc.c
    third_party/LightPcapNg/src/light_compression.c
    third_party/LightPcapNg/src/light_internal.c
    third_party/LightPcapNg/src/light_io.c
    third_party/LightPcapNg/src/light_manipulate.c
    third_party/LightPcapNg/src/light_null_compression.c
    third_party/LightPcapNg/src/light_option.c
    third_party/LightPcapNg/src/light_pcapng_cont.c
    third_party/LightPcapNg/src/light_pcapng_ext.c
    third_party/LightPcapNg/src/light_pcapng.c
    third_party/LightPcapNg/src/light_platform.c
    third_party/LightPcapNg/src/light_zstd_compression.c
)

set(EXTENSION_SOURCES
    src/pqcap_reader_extension.cpp
    src/pqcap_copy_function.cpp
    src/pqcap_packet_table.cpp
    src/pqcap_footer.cpp
    src/pqcap_subfile_fs.cpp
    ${LIGHT_PCAPNG_SOURCES}
)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

target_include_directories(${EXTENSION_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/LightPcapNg/include
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/extension/parquet/include
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/extension/parquet
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/third_party/parquet
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/third_party/thrift
)
target_include_directories(${LOADABLE_EXTENSION_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/LightPcapNg/include
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/extension/parquet/include
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/extension/parquet
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/third_party/parquet
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/third_party/thrift
)
target_compile_definitions(${EXTENSION_NAME} PRIVATE UNIVERSAL)
target_compile_definitions(${LOADABLE_EXTENSION_NAME} PRIVATE UNIVERSAL)

install(
    TARGETS ${EXTENSION_NAME}
    EXPORT "${DUCKDB_EXPORT_SET}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
)
