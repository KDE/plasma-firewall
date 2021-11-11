# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

find_package(Qt5 ${QT_MIN_VERSION} CONFIG REQUIRED COMPONENTS
    Quick
    Xml
    X11Extras
)

find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS
    Plasma
    PlasmaQuick
    I18n
    Declarative
    Auth
    Config
)


add_library(networkstatus STATIC)
target_sources(networkstatus PRIVATE
    conectionsmodel.cpp
    conectionsmodel.h
    netstatclient.cpp
    netstatclient.h
    netstathelper.cpp
    netstathelper.h
)

target_link_libraries(networkstatus
    kcm_firewall_core
    Qt::Core
    Qt::Quick
    Qt::X11Extras
    KF5::CoreAddons
    KF5::ConfigCore
    KF5::Auth
    KF5::I18n
)
