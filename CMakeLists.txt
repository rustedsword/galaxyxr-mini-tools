cmake_minimum_required (VERSION 3.25)
project (galaxyxr_mini_tools LANGUAGES C)

set (CMAKE_C_STANDARD 23)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS OFF)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release)
endif ()

add_compile_definitions (_GNU_SOURCE)
add_compile_options (-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes)

add_subdirectory (lib)
add_subdirectory (bdf_mac)
add_subdirectory (map_super)
add_subdirectory (panels_off)
add_subdirectory (rpmb)
add_subdirectory (uefivars)
add_subdirectory (unlock_data)
