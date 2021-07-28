# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

set(ufw_backend_SRCS
    ufwclient.cpp
    ufwlogmodel.cpp
)

kcoreaddons_add_plugin(
    ufwbackend
    SOURCES ${ufw_backend_SRCS}
    INSTALL_NAMESPACE "kf5/plasma_firewall")

target_link_libraries(ufwbackend
    kcm_firewall_core
)

add_subdirectory(helper)
