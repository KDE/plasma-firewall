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
kcmutils_generate_desktop_file(kcm_firewall)
target_sources(kcm_firewall PRIVATE
   kcm.cpp
   kcm.h
)
target_link_libraries(kcm_firewall
    Qt::Quick
    Qt::DBus

    KF6::CoreAddons
    KF6::Declarative
    KF6::I18n
    KF6::QuickAddons
    KF6::AuthCore

    kcm_firewall_core
    networkstatus
)

install(TARGETS kcm_firewall DESTINATION ${KDE_INSTALL_PLUGINDIR}/plasma/kcms/systemsettings)

kpackage_install_package(package kcm_firewall kcms)
