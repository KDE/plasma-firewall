# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
if(BUILD_FIREWALLD_BACKEND)
    add_subdirectory(firewalld)
endif()
if(BUILD_UFW_BACKEND)
    add_subdirectory(ufw)
endif()

add_subdirectory(netstat)
