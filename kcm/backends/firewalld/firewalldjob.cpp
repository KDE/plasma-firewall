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

#include <QDebug>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusPendingCall>
#include <QtDBus/QDBusPendingReply>

#include <KLocalizedString>

#include "dbustypes.h"
#include "firewalldjob.h"

Q_LOGGING_CATEGORY(FirewallDJobDebug, "firewalld.job")

namespace HELPER
{
const QString KCM_FIREWALLD_DIR = QStringLiteral("/etc/kcm/firewalld");
const QString LOG_FILE = QStringLiteral("/var/log/firewalld.log");
const QString BUS = QStringLiteral("org.fedoraproject.FirewallD1");
const QString PATH = QStringLiteral("/org/fedoraproject/FirewallD1");
const QString INTERFACE = QStringLiteral("org.fedoraproject.FirewallD1.direct");

}

namespace SAVE
{
const QString BUS = QStringLiteral("org.fedoraproject.FirewallD1");
const QString PATH = QStringLiteral("/org/fedoraproject/FirewallD1");
const QString INTERFACE = QStringLiteral("org.fedoraproject.FirewallD1");
const QString METHOD = QStringLiteral("runtimeToPermanent");

}

enum {
    DBUSFIREWALLDDERROR = KJob::UserDefinedError,
};

FirewalldJob::FirewalldJob() {};
FirewalldJob::FirewalldJob(const QByteArray &call, const QVariantList &args, const FirewalldJob::JobType &type)
    : KJob()
    , m_type(type)
{
    setFirewalldMessage(call, args);
};
FirewalldJob::FirewalldJob(const FirewalldJob::JobType &type)
    : KJob()
    , m_type(type) {};

void FirewalldJob::setFirewalldMessage(const QByteArray &call, const QVariantList &args)
{
    if (!m_type) {
        m_call = call;
        m_args = args;
    }
}

void FirewalldJob::firewalldAction(const QByteArray &method, const QVariantList &args)
{
    QDBusMessage call = QDBusMessage::createMethodCall(HELPER::BUS, HELPER::PATH, HELPER::INTERFACE, method);
    call.setArguments(args);
    QDBusPendingCall message = QDBusConnection::systemBus().asyncCall(call);
    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(message, this);
    if (args.isEmpty()) {
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *watcher) {
            QDBusPendingReply<QList<firewalld_reply>> reply = *watcher;
            watcher->deleteLater();
            if (reply.isError()) {
                setErrorText(reply.error().message());
                setError(DBUSFIREWALLDDERROR);
                qDebug() << errorString();
                emitResult();
                return;
            }

            m_firewalldreply = reply.value();
            emitResult();
            return;
        });
    } else {
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *watcher) {
            QDBusPendingReply<> reply = *watcher;
            watcher->deleteLater();

            if (reply.isError()) {
                setErrorText(reply.reply().errorMessage());
                setError(DBUSFIREWALLDDERROR);
                qDebug() << errorString();
                emitResult();
                return;
            }
            /* Firewalld does not save directly, need to call the another dbus interface
             * namespace SAVE define the bus,path,interface and method.
             * the method saveFirewalld do this call.
             */
            emitResult();
            return;
        });
    }
}

QList<firewalld_reply> FirewalldJob::get_firewalldreply()
{
    return m_firewalldreply;
}

FirewalldJob::~FirewalldJob() = default;

void FirewalldJob::start()
{
    switch (m_type) {
    case FirewalldJob::FIREWALLD:
        qCDebug(FirewallDJobDebug) << "firewalld " << m_call << m_args;
        firewalldAction(m_call, m_args);
        break;
    case FirewalldJob::SAVEFIREWALLD:
        qCDebug(FirewallDJobDebug) << i18n("firewalld saving (runtime to permanent)");
        saveFirewalld();
        break;
    default:
        emitResult();
        return;
    }
};

QString FirewalldJob::name()
{
    return m_type == FirewalldJob::SAVEFIREWALLD ? QString("firewalld saving") : QString("firewalld %1").arg(QString(m_call));
}

void FirewalldJob::saveFirewalld()
{
    QDBusPendingCall message = QDBusConnection::systemBus().asyncCall(QDBusMessage::createMethodCall(SAVE::BUS, SAVE::PATH, SAVE::INTERFACE, SAVE::METHOD));

    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(message, this);

    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *watcher) {
        QDBusPendingReply<> reply = *watcher;
        watcher->deleteLater();

        if (reply.isError()) {
            setErrorText(reply.error().message());
            setError(DBUSFIREWALLDDERROR);
            qDebug() << errorString();
            emitResult();
        }
        return;
    });
};
