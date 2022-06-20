# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

include(GenerateExportHeader)

add_library(kcm_firewall_core
    appprofiles.cpp
    appprofiles.h
    firewallclient.cpp
    firewallclient.h
    ifirewallclientbackend.cpp
    ifirewallclientbackend.h
    ipvalidator.cpp
    ipvalidator.h
    loglistmodel.cpp
    loglistmodel.h
    profile.cpp
    profile.h
    rule.cpp
    rule.h
    rulelistmodel.cpp
    rulelistmodel.h
    types.cpp
    types.h
)

generate_export_header(kcm_firewall_core)

target_include_directories(kcm_firewall_core PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")

target_link_libraries(kcm_firewall_core
    Qt::Quick
    KF5::CoreAddons
    KF5::Declarative
    KF5::I18n
    KF5::QuickAddons
    KF5::AuthCore
)

install(TARGETS kcm_firewall_core ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})
