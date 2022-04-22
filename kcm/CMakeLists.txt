# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    .
)

add_definitions(-DTRANSLATION_DOMAIN=\"kcm_firewall\")
add_subdirectory(core)
add_subdirectory(backends)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/version.h)



add_library(kcm_firewall MODULE)
target_sources(kcm_firewall PRIVATE
   kcm.cpp
   kcm.h
)
target_link_libraries(kcm_firewall
    Qt::Quick
    Qt::DBus

    KF5::CoreAddons
    KF5::Declarative
    KF5::I18n
    KF5::QuickAddons
    KF5::AuthCore

    kcm_firewall_core
    networkstatus
)

install(FILES kcm_firewall.desktop DESTINATION ${KDE_INSTALL_APPDIR})
install(TARGETS kcm_firewall DESTINATION ${KDE_INSTALL_PLUGINDIR}/plasma/kcms/systemsettings)

kpackage_install_package(package kcm_firewall kcms)
