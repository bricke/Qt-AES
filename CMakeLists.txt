cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(QtAES VERSION 1.1 LANGUAGES CXX)

set(QTAES_STANDALONE_BUILD OFF)
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(QTAES_STANDALONE_BUILD ON)
endif()

option(QTAES_ENABLE_AESNI   "${PROJECT_NAME}: Enable AES-NI"            OFF)
option(QTAES_ENABLE_INSTALL "${PROJECT_NAME}: Enable install"            ${QTAES_STANDALONE_BUILD})
option(QTAES_ENABLE_TESTS   "${PROJECT_NAME}: Enable tests"              ${QTAES_STANDALONE_BUILD})
option(QTAES_ENABLE_WERROR  "${PROJECT_NAME}: Treat warnings as errors"  OFF)

# GNUInstallDirs is needed for CMAKE_INSTALL_* variables used in
# target_include_directories and the install() calls below.
include(GNUInstallDirs)

if(QTAES_STANDALONE_BUILD)
    if(NOT CMAKE_CXX_STANDARD)
        set(CMAKE_CXX_STANDARD 11)
        set(CMAKE_CXX_STANDARD_REQUIRED ON)
        set(CMAKE_CXX_EXTENSIONS OFF)
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(
            -Wall
            -Wextra
            -pedantic
            $<$<BOOL:${QTAES_ENABLE_WERROR}>:-Werror>)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        add_compile_options(
            /W4
            $<$<BOOL:${QTAES_ENABLE_WERROR}>:/WX>)
    endif()
endif()

# Locate Qt (prefer Qt6, fall back to Qt5) and derive the versioned package name.
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
set(QT_PACKAGE_NAME Qt${QT_VERSION_MAJOR})

set(QT_COMPS Core)
if(QTAES_ENABLE_TESTS)
    list(APPEND QT_COMPS Test)
endif()
find_package(${QT_PACKAGE_NAME} REQUIRED COMPONENTS ${QT_COMPS})

add_library(QtAES)

# Per-target MOC/RCC — avoid polluting parent builds when used as a subdirectory.
set_target_properties(QtAES PROPERTIES AUTOMOC ON)

if(NOT QTAES_STANDALONE_BUILD)
    add_library(${PROJECT_NAME}::QtAES ALIAS QtAES)
endif()

# Generate export header unconditionally so that builds with
# -DBUILD_SHARED_LIBS=ON work correctly in all modes.
include(GenerateExportHeader)
generate_export_header(QtAES EXPORT_MACRO_NAME QTAESSHARED_EXPORT)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/QAESEncryption" "#include \"qaesencryption.h\"")

target_sources(QtAES
    PRIVATE
        qaesencryption.cpp
        qaesencryption.h)

target_include_directories(QtAES
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}>)

target_compile_definitions(QtAES
    PRIVATE
        QT_DISABLE_DEPRECATED_BEFORE=0x060000)

if(QTAES_ENABLE_AESNI)
    # AES-NI uses x86 intrinsics and inline asm — reject unsupported architectures at
    # configure time rather than letting the build fail with a cryptic compiler error.
    if(NOT (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i[3-6]86|x86"))
        message(FATAL_ERROR
            "QTAES_ENABLE_AESNI is only supported on x86/x86-64. "
            "Detected processor: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    include(CheckCXXCompilerFlag)

    target_sources(QtAES
        PRIVATE
            aesni/aesni-key-exp.h
            aesni/aesni-key-init.h
            aesni/aesni-enc-ecb.h
            aesni/aesni-enc-cbc.h)

    target_compile_definitions(QtAES
        PRIVATE
            USE_INTEL_AES_IF_AVAILABLE)

    check_cxx_compiler_flag(-maes CXX_COMPILER_HAS_FLAG_MAES)

    target_compile_options(QtAES
        PRIVATE
            $<$<BOOL:${CXX_COMPILER_HAS_FLAG_MAES}>:-maes>)
endif()

target_link_libraries(QtAES
    PUBLIC
        ${QT_PACKAGE_NAME}::Core)

if(QTAES_ENABLE_TESTS)
    enable_testing()

    add_executable(AESTest)

    # Per-target RCC for the test executable.
    set_target_properties(AESTest PROPERTIES AUTOMOC ON AUTORCC ON)

    target_sources(AESTest
        PRIVATE
            main.cpp
            res.qrc
            unit_test/aestest.cpp
            unit_test/aestest.h)

    # Qt::Core is already a transitive dependency via QtAES; only Test is needed here.
    target_link_libraries(AESTest
        PRIVATE
            QtAES
            ${QT_PACKAGE_NAME}::Test)

    add_test(
        NAME AESTest
        COMMAND AESTest)
endif()

if(QTAES_ENABLE_INSTALL)
    include(CMakePackageConfigHelpers)

    install(
        TARGETS QtAES
        EXPORT ${PROJECT_NAME}Targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    install(
        FILES
            qaesencryption.h
            "${CMAKE_CURRENT_BINARY_DIR}/qtaes_export.h"
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/QAESEncryption"
        DESTINATION
            ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

    install(
        FILES
            LICENSE
            README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

    install(
        EXPORT ${PROJECT_NAME}Targets
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
        NAMESPACE ${PROJECT_NAME}::)

    configure_file(${PROJECT_NAME}Config.cmake.in ${PROJECT_NAME}Config.cmake @ONLY)

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        COMPATIBILITY AnyNewerVersion)

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
endif()
