cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(QtAES VERSION 1.1 LANGUAGES CXX)

set(QTAES_STANDALONE_BUILD OFF)
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(QTAES_STANDALONE_BUILD ON)
endif()

option(QTAES_ENABLE_AESNI "${PROJECT_NAME}: Enable AES-NI" OFF)
option(QTAES_ENABLE_INSTALL "${PROJECT_NAME}: Enable install" ${QTAES_STANDALONE_BUILD})
option(QTAES_ENABLE_TESTS "${PROJECT_NAME}: Enable tests" ${QTAES_STANDALONE_BUILD})
option(QTAES_ENABLE_WERROR "${PROJECT_NAME}: Treat warnings as errors" OFF)

set(QTAES_QT_VERSION 5 CACHE STRING "${PROJECT_NAME}: Qt version to use")

if(QTAES_ENABLE_INSTALL)
    include(GNUInstallDirs)
endif()

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

if(QTAES_QT_VERSION MATCHES "^([56])([.]|$)")
    set(QT_PACKAGE_NAME Qt${CMAKE_MATCH_1})

    set(QT_COMPS Core)
    if(QTAES_ENABLE_TESTS)
        list(APPEND QT_COMPS Test)
    endif()

    find_package(${QT_PACKAGE_NAME} ${QTAES_QT_VERSION} REQUIRED COMPONENTS ${QT_COMPS})
else()
    message(FATAL_ERROR "Qt version '${QTAES_QT_VERSION}' is not supported")
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

add_library(QtAES)

if(NOT QTAES_STANDALONE_BUILD)
    add_library(${PROJECT_NAME}::QtAES ALIAS QtAES)
    generate_export_header(QtAES EXPORT_MACRO_NAME QTAESSHARED_EXPORT)
endif()

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/QAESEncryption" "#include \"qaesencryption.h\"")

target_sources(QtAES
    PRIVATE
        qaesencryption.cpp
        qaesencryption.h)

target_include_directories(QtAES
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_definitions(QtAES
    PRIVATE
        QT_DISABLE_DEPRECATED_BEFORE=0x060000)

if(QTAES_ENABLE_AESNI)
    include(CheckCXXCompilerFlag)

    target_sources(QtAES
        PRIVATE
            aesni/aesni-key-exp.h
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

    target_sources(AESTest
        PRIVATE
            main.cpp
            res.qrc
            unit_test/aestest.cpp
            unit_test/aestest.h
            unit_test/longText.txt)

    target_link_libraries(AESTest
        PRIVATE
            QtAES
            ${QT_PACKAGE_NAME}::Core
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
