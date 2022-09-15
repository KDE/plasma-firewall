# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

cmake_minimum_required(VERSION 3.16)
#-----------------------------------------------------------------------------
#                           GENERAL CONFIGURATION
#-----------------------------------------------------------------------------
project(plasma-firewall)
set(PROJECT_VERSION "5.25.80")

set(KF5_MIN_VERSION "5.98.0")
set(KDE_COMPILERSETTINGS_LEVEL "5.82")
set(QT_MIN_VERSION "5.15.2")

set(CMAKE_AUTOMOC TRUE)
set(CMAKE_AUTORCC TRUE)

#-----------------------------------------------------------------------------
#                                OPTIONS
#-----------------------------------------------------------------------------

include(FeatureSummary)

option(BUILD_FIREWALLD_BACKEND "Build the firewalld backend" ON)
add_feature_info(FIREWALLD_BACKEND ${BUILD_FIREWALLD_BACKEND} "Build the FirewallD backend")

option(BUILD_UFW_BACKEND "Build the Uncomplicated Firewall (UFW) backend" ON)
add_feature_info(UFW_BACKEND ${BUILD_UFW_BACKEND} "Build the Uncomplicated Firewall (UFW) backend")

#-----------------------------------------------------------------------------
#                              DEPENDENCIES
#-----------------------------------------------------------------------------
# Python3 (search for this first so that we will not get Python2 by accident)
find_package(PythonInterp 3 REQUIRED)
# KDE5
find_package(ECM ${KF5_MIN_VERSION} REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
include(KDEInstallDirs)
include(KDECompilerSettings)
include(KDECMakeSettings)

# Qt5
find_package(Qt${QT_MAJOR_VERSION} REQUIRED COMPONENTS
    Core
    Qml
    DBus
)


add_definitions(-DQT_DISABLE_DEPRECATED_BEFORE=0x050f00)
add_definitions(-DKF_DISABLE_DEPRECATED_BEFORE_AND_AT=0x055800)


find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS 
    CoreAddons
    KCMUtils
    I18n
    Declarative
)


#-----------------------------------------------------------------------------
#                               SOURCES
#-----------------------------------------------------------------------------
add_subdirectory(kcm)

enable_testing(true)
add_subdirectory(tests)

#-----------------------------------------------------------------------------
#                               Clang Format
#-----------------------------------------------------------------------------
include(KDEClangFormat)
file(GLOB_RECURSE ALL_CLANG_FORMAT_SOURCE_FILES *.cpp *.h)
kde_clang_format(${ALL_CLANG_FORMAT_SOURCE_FILES})

install(FILES org.kde.plasma.firewall.metainfo.xml DESTINATION ${KDE_INSTALL_METAINFODIR})

#-----------------------------------------------------------------------------
#                               BUILD SUMMARY
#-----------------------------------------------------------------------------
feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
