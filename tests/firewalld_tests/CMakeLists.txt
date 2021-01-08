add_executable(firewalld_tests
    main.cpp
)

target_link_libraries(firewalld_tests
    Qt5::Core
    kcm_firewall_core
)
