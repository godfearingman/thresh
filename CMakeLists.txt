cmake_minimum_required(VERSION 3.24)
project(thresh LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

set(ASMJIT_STATIC        ON  CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(raw_pdb
    GIT_REPOSITORY https://github.com/MolecularMatters/raw_pdb.git
    GIT_TAG        main)          

FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.0)

FetchContent_Declare(asmjit
    GIT_REPOSITORY https://github.com/asmjit/asmjit.git
    GIT_TAG        master)        

FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.14.1)

FetchContent_Declare(cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.4.2)

FetchContent_Declare(vtil
    GIT_REPOSITORY https://github.com/vtil-project/VTIL-Core.git
    GIT_TAG        master)

set(VTIL_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(raw_pdb zydis asmjit spdlog cli11 vtil)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS src/*.cpp)
add_executable(thresh ${SOURCES})

target_compile_definitions(thresh PRIVATE _SILENCE_ALL_CXX23_DEPRECATION_WARNINGS)
target_link_options(thresh PRIVATE /STACK:536870912)   

target_link_libraries(thresh PRIVATE
    raw_pdb
    Zydis
    asmjit::asmjit
    spdlog::spdlog_header_only
    CLI11::CLI11
    VTIL
)

add_custom_target(run COMMAND thresh DEPENDS thresh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
