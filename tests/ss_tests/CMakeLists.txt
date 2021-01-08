add_executable(ss_tests
    main.cpp
)

target_link_libraries(ss_tests
    Qt5::Core
    kcm_firewall_core
)
