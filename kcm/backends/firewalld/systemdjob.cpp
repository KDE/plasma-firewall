// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2020 Lucas Biaggi <lbjanuario@gmail.com>
/*
 * Firewalld backend for plasma firewall
 */

#include <KLocalizedString>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCall>
#include <QDBusPendingReply>
#include <QDebug>
#include <QTimer>

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
SystemdJob::SystemdJob(SYSTEMD::actions action)
    : KJob()
    , m_action(action){};

void SystemdJob::systemdAction(const SYSTEMD::actions value)
{
    QDBusMessage call;
    switch (value) {
    case SYSTEMD::START:
        call = QDBusMessage::createMethodCall(SYSTEMD::BUS, SYSTEMD::PATH, SYSTEMD::INTERFACE, QStringLiteral("StartUnit"));
        call.setArguments({"firewalld.service", "fail"});
        break;
    case SYSTEMD::STOP:
        call = QDBusMessage::createMethodCall(SYSTEMD::BUS, SYSTEMD::PATH, SYSTEMD::INTERFACE, QStringLiteral("StopUnit"));
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
        QTimer *timer = new QTimer(this);
        timer->setInterval(1500);
        connect(timer, &QTimer::timeout, this, [this]() {
            emitResult();
        });
        timer->start();
        // return;
    });
    // return;
}

SystemdJob::~SystemdJob() = default;

void SystemdJob::start()
{
    systemdAction(m_action);
};
