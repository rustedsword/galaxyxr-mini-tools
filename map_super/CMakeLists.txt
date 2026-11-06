add_executable (map_super map_super.c)
target_link_libraries (map_super PRIVATE dm)
install (TARGETS map_super)
