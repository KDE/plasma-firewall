include(GenerateExportHeader)

if(BUILD_FIREWALLD)
    add_compile_definitions(FIREWALLD)
endif()

add_library(kcm_firewall_core
    firewallclient.cpp
    ifirewallclientbackend.cpp
    rule.cpp
    rulewrapper.cpp
    types.cpp
    loglistmodel.cpp
    rulelistmodel.cpp
    profile.cpp
    appprofiles.cpp
)

generate_export_header(kcm_firewall_core)

target_include_directories(kcm_firewall_core PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")

target_link_libraries(kcm_firewall_core
    Qt5::Quick
    KF5::CoreAddons
    KF5::Declarative
    KF5::I18n
    KF5::QuickAddons
    KF5::Auth
)

install(TARGETS kcm_firewall_core ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})
