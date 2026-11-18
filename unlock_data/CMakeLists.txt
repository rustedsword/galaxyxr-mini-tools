add_executable (unlock_data unlock_data.c)
target_link_libraries (unlock_data PRIVATE vold)
install (TARGETS unlock_data)
