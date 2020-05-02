cmake_minimum_required(VERSION 3.8)
#-----------------------------------------------------------------------------
#                           GENERAL CONFIGURATION
#-----------------------------------------------------------------------------
project(plasma-firewall)

set(KF5_MIN_VERSION "5.30.0")
set(QT_MIN_VERSION "5.12.0")

set(CMAKE_AUTOMOC TRUE)
set(CMAKE_AUTORCC TRUE)

#-----------------------------------------------------------------------------
#                              DEPENDENCIES
#-----------------------------------------------------------------------------
# Python3 (search for this first so that we will not get Python2 by accident)
find_package(PythonInterp 3 REQUIRED)

# Qt5
find_package(Qt5 REQUIRED COMPONENTS
    Core
    Qml
    DBus
    X11Extras
)

# KDE5
find_package(ECM REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECompilerSettings)
include(KDECMakeSettings)

include(FeatureSummary)

find_package(KF5 REQUIRED COMPONENTS 
    CoreAddons
    KCMUtils
    I18n
    Plasma
    PlasmaQuick
    KDELibs4Support
    Declarative
)


#-----------------------------------------------------------------------------
#                               SOURCES
#-----------------------------------------------------------------------------
add_subdirectory(kcm)
include(KDEClangFormat)
file(GLOB_RECURSE ALL_CLANG_FORMAT_SOURCE_FILES kcm/*.cpp kcm/*.h)
kde_clang_format(${ALL_CLANG_FORMAT_SOURCE_FILES})
#-----------------------------------------------------------------------------
#                               BUILD SUMMARY
#-----------------------------------------------------------------------------
feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
