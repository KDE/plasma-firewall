add_executable(ufw_tests
    main.cpp
)

target_link_libraries(ufw_tests
    Qt5::Core
    kcm_firewall_core
)
