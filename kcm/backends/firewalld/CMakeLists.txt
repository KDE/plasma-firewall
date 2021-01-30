# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Lucas Biaggi <lbjanuario@gmail.com>
set(firewalld_backend_SRCS
    firewalldclient.cpp
    firewalldlogmodel.cpp
    firewalldjob.cpp
    systemdjob.cpp
    dbustypes.cpp
)

kcoreaddons_add_plugin(
    firewalldbackend
    SOURCES ${firewalld_backend_SRCS}
    JSON firewalldbackend.json
    INSTALL_NAMESPACE "kf5/plasma_firewall")

target_link_libraries(firewalldbackend
    Qt::DBus
    kcm_firewall_core
)
