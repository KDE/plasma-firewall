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

set(kcm_SRCS
   kcm.cpp
   kcm.h
)

add_library(kcm_firewall MODULE ${kcm_SRCS})

target_link_libraries(kcm_firewall
    Qt::Quick
    Qt::X11Extras
    Qt::DBus

    KF5::CoreAddons
    KF5::Declarative
    KF5::I18n
    KF5::QuickAddons
    KF5::Auth

    kcm_firewall_core
    networkstatus
)

kcoreaddons_desktop_to_json(kcm_firewall kcm_firewall.desktop SERVICE_TYPES kcmodule.desktop)

#this desktop file is installed only for retrocompatibility with sycoca
install(FILES kcm_firewall.desktop DESTINATION ${SERVICES_INSTALL_DIR})
install(TARGETS kcm_firewall DESTINATION ${PLUGIN_INSTALL_DIR}/kcms)

kpackage_install_package(package kcm_firewall kcms)
