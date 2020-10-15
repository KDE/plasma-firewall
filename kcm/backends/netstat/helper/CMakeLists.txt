# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

# Find includes in corresponding build directories
include_directories(${CMAKE_BINARY_DIR})

# Instruct CMake to run moc automatically when needed.
set(CMAKE_AUTOMOC ON)

find_package(Qt5 ${QT_MIN_VERSION} CONFIG REQUIRED COMPONENTS
    Core
    )


find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS
    I18n
    Auth
    )

add_executable(kde_netstat_helper netstathelper.cpp)
target_link_libraries(kde_netstat_helper Qt5::Core KF5::I18n KF5::Auth)

install(TARGETS kde_netstat_helper DESTINATION ${KAUTH_HELPER_INSTALL_DIR})
kauth_install_helper_files(kde_netstat_helper org.kde.netstat root)

kauth_install_actions(org.kde.netstat org.kde.netstat.actions)
