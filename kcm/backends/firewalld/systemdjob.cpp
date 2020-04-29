/*
 * Firewalld backend for plasma firewall
 *
 * Copyright 2020 Lucas Biaggi <lbjanuario@gmail.com>
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

#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusPendingCall>
#include <QtDBus/QDBusPendingReply>
#include <QDebug>

#include "systemdjob.h"

namespace SYSTEMD {
    const QString BUS = QStringLiteral("org.freedesktop.systemd1");
    const QString PATH = QStringLiteral("/org/freedesktop/systemd1");
    const QString INTERFACE = QStringLiteral("org.freedesktop.systemd1.Manager");
}

enum {
    DBUSSYSTEMDERROR = KJob::UserDefinedError,
};
SystemdJob::SystemdJob(const SYSTEMD::actions &action): KJob(), m_action(action) {};

void SystemdJob::systemdAction(const SYSTEMD::actions value) {


    QDBusMessage call;
    switch(value) {

        case SYSTEMD::START:
            call = QDBusMessage::createMethodCall(SYSTEMD::BUS,SYSTEMD::PATH,SYSTEMD::INTERFACE,"StartUnit");
            call.setArguments({"firewalld.service", "fail"});
            break;
        case SYSTEMD::STOP:
            call = QDBusMessage::createMethodCall(SYSTEMD::BUS,SYSTEMD::PATH,SYSTEMD::INTERFACE,"StopUnit");
            call.setArguments({"firewalld.service", "fail"});
            break;

        default:
            setErrorText("Invalid Call");
            setError(DBUSSYSTEMDERROR);
            emitResult();
    }
    QDBusPendingCall message = QDBusConnection::systemBus().asyncCall(call);
    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(message, this);

    /* waiting for start/stop of firewalld */
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *watcher) {
            QDBusPendingReply<> reply = *watcher;
            watcher->deleteLater();
            if (reply.isError()) {
                setErrorText(reply.reply().errorMessage());
                setError(DBUSSYSTEMDERROR);
            }
            emitResult();
            return;
    });
}

SystemdJob::~SystemdJob() = default;

void SystemdJob::start() {
    qDebug() << "systemd " << m_action;
    systemdAction(m_action);
};
