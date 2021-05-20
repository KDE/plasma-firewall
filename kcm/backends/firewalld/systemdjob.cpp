// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2020 Lucas Biaggi <lbjanuario@gmail.com>
/*
 * Firewalld backend for plasma firewall
 */

#include <QDebug>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCall>
#include <QDBusPendingReply>

#include <KLocalizedString>

#include "systemdjob.h"

Q_LOGGING_CATEGORY(SystemDJobDebug, "systemd.job")

namespace SYSTEMD
{
const QString BUS = QStringLiteral("org.freedesktop.systemd1");
const QString PATH = QStringLiteral("/org/freedesktop/systemd1");
const QString INTERFACE = QStringLiteral("org.freedesktop.systemd1.Manager");
}

enum {
    DBUSSYSTEMDERROR = KJob::UserDefinedError,
};
SystemdJob::SystemdJob(const SYSTEMD::actions &action)
    : KJob()
    , m_action(action) {};

void SystemdJob::systemdAction(const SYSTEMD::actions value)
{
    QDBusMessage call;
    switch (value) {
    case SYSTEMD::START:
        call = QDBusMessage::createMethodCall(SYSTEMD::BUS, SYSTEMD::PATH, SYSTEMD::INTERFACE, "StartUnit");
        call.setArguments({"firewalld.service", "fail"});
        break;
    case SYSTEMD::STOP:
        call = QDBusMessage::createMethodCall(SYSTEMD::BUS, SYSTEMD::PATH, SYSTEMD::INTERFACE, "StopUnit");
        call.setArguments({"firewalld.service", "fail"});
        break;

    default:
        setErrorText(i18n("Invalid Call"));
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
    return;
}

SystemdJob::~SystemdJob() = default;

void SystemdJob::start()
{
    // Calling those too quickly can seriously break firewalld.
    // Known Error, SystemD bug: https://github.com/systemd/systemd/issues/11305
    // firewalld.client: Job Error:  100 "Transaction for firewalld.service/start is destructive
    // (firewalld.service has 'stop' job queued, but 'start' is included in transaction)."
    //
    // Adding a timer of around 8 seconds fixes the issue on my computer,
    // but that does not seems to be a good thing.
    systemdAction(m_action);
};
