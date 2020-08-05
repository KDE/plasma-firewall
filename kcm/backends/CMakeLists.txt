if(BUILD_FIREWALLD)
    add_subdirectory(firewalld)
else()
    add_subdirectory(ufw)
endif()

add_subdirectory(netstat)
