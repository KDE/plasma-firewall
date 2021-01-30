add_executable(firewall_tests
    main.cpp
)

target_link_libraries(firewall_tests
    Qt::Core
    kcm_firewall_core
)
