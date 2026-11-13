find_package (LibXml2 REQUIRED)

add_executable (bt_nvm bt_nvm.c)
target_link_libraries (bt_nvm PRIVATE LibXml2::LibXml2)
install (TARGETS bt_nvm)
