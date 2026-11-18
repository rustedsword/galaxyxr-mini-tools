add_executable (mount_android_userdata mount_android_userdata.c)
target_link_libraries (mount_android_userdata PRIVATE vold)
install (TARGETS mount_android_userdata)
