/*
 * FIREWALLD KControl Module
 *
 * Copyright 2011 Craig Drummond <craig.p.drummond@gmail.com>
 *
 * ----
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "helper.h"
#include <QDebug>
#include <QString>
#include <QDBusInterface>
#include "firewalld_interface_config.h"


namespace {
    //const QString KCM_FIREWALLD_DIR = QStringLiteral("/etc/kcm_firewalld");
    const QString LOG_FILE = QStringLiteral("/var/log/firewalld.log");
    const QString SERVICE_NAME = "org.fedoraproject.FirewallD1";
    const QString INTERFACE_NAME = SERVICE_NAME + ".direct";
    const QString DBUS_PATH = "/org/fedoraproject/FirewallD1";


   
}

namespace FIREWALLD {
  
}//end firewalld namespace
