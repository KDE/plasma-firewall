// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2020 Lucas Biaggi <lbjanuario@gmail.com>

#ifndef FIREWALLDJOB_H
#define FIREWALLDJOB_H

#include <KJob>
#include <QDBusPendingCallWatcher>
#include <types.h>

#include <QLoggingCategory>

#include "dbustypes.h"

Q_DECLARE_LOGGING_CATEGORY(FirewallDJobDebug)

class FirewalldJob : public KJob
{
    Q_OBJECT

public:
    enum JobType { SIMPLELIST, FIREWALLD, SAVEFIREWALLD, LISTSERVICES, SIMPLIFIEDRULE };
    FirewalldJob(const QByteArray &call, const QVariantList &args = {}, const FirewalldJob::JobType &type = FIREWALLD);
    FirewalldJob(const FirewalldJob::JobType &type);
    FirewalldJob();
    ~FirewalldJob();
    void start() override;
    QList<firewalld_reply> getFirewalldreply();
    QStringList getServices();
    QString name();

private:
    template<typename T>
    T connectCall(QDBusPendingCallWatcher *watcher);
    void connectCall(QDBusPendingCallWatcher *watcher);
    void saveFirewalld();
    void firewalldAction(const QByteArray &method, const QVariantList &args = {});
    void firewalldAction(const QString &bus, const QString &path, const QString &interface, const QString &method, const QVariantList &args = {});
    JobType m_type;
    QByteArray m_call;
    QVariantList m_args;
    QStringList m_services = {};
    QList<firewalld_reply> m_firewalldreply = {};
};
#endif
