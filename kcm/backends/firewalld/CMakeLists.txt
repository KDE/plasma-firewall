set(firewalld_backend_SRCS
    firewalldclient.cpp
)

kcoreaddons_add_plugin(
    firewalldbackend
    SOURCES ${firewalld_backend_SRCS}
    JSON firewalldbackend.json
    INSTALL_NAMESPACE "kf5/plasma_firewall")

target_link_libraries(firewalldbackend
    Qt5::DBus
    KF5::CoreAddons
    kcm_firewall_core
)
