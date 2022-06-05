cmake_minimum_required(VERSION 3.0.0)
project(fuzzy VERSION 0.1.0 LANGUAGES C)

# include(CTest)
# enable_testing()

file(GLOB all_SRCS
    "${fuzzy_SOURCE_DIR}/src/*.h"
    "${fuzzy_SOURCE_DIR}/src/*.c"
)

add_executable(fuzzy ${all_SRCS})

target_include_directories(
    fuzzy PRIVATE ${fuzzy_SOURCE_DIR}/src
)

# Funktioniert nicht! Irgendwas stimmt im folgenden Code nicht, 
# es kompiliert fehlerlos aber ausführen lässt es sich nicht.
# Also für jetzt: Wrapper benutzen mittels FetchContent

# This is to make Cmake look in the /cmake directory, where
# FindSodium.cmake is located. This includes the libsodium library.
# set(sodium_DIR "C:/lib/libsodium-1.0.18-stable-mingw/libsodium-win64")
# set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
# find_package(Sodium REQUIRED)
# if(${Sodium_FOUND})
#     message("Sodium found!!!!!")
#     target_include_directories(fuzzy PUBLIC ${sodium_INCLUDE_DIR})
#     set(LIBS ${LIBS} ${sodium_LIBRARY_RELEASE})
#     target_link_libraries(fuzzy ${LIBS})
# endif()



# Wrapper um libsodium, wird lokal geklont und kompiliert:

include(FetchContent)

FetchContent_Declare(Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
)
set(SODIUM_DISABLE_TESTS ON)
FetchContent_MakeAvailable(Sodium)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        sodium
)







set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)


# poop machine on the go!
# reject
# 404 not found
# yoni not found
# find_program(BERTILLE)
# include(CheckCXXCompilerFlag)
# rainbow
# i love gaYS
# HE IS JOB_POOL_COMPILE POOPING find_package(LATEXOK
# POOPING FILE COMPLETE!
# 8022022
# bisous code erledigt
# file
# found)