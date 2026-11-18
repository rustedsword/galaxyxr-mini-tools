add_library (dm STATIC dm.c)
target_include_directories (dm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
add_library (vold STATIC vold.c)
target_link_libraries (vold PUBLIC dm)
