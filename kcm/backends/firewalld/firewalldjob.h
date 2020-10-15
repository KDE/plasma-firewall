// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2020 Lucas Biaggi <lbjanuario@gmail.com>

#ifndef FIREWALLDJOB_H
#define FIREWALLDJOB_H

#include <KJob>
#include <types.h>

#include <QLoggingCategory>

#include "dbustypes.h"

Q_DECLARE_LOGGING_CATEGORY(FirewallDJobDebug)

class FirewalldJob : public KJob
{
    Q_OBJECT

public:
    enum JobType { FIREWALLD, SAVEFIREWALLD, FAKEJOB };
    FirewalldJob(const QByteArray &call, const QVariantList &args = {}, const JobType &type = FIREWALLD);
    FirewalldJob(const JobType &type);
    FirewalldJob();
    ~FirewalldJob();
    void start() override;
    QList<firewalld_reply> get_firewalldreply();
    QString name();

private:
    void setFirewalldMessage(const QByteArray &call, const QVariantList &args = {});
    void saveFirewalld();
    void firewalldAction(const QByteArray &method, const QVariantList &args = {});
    QList<firewalld_reply> m_firewalldreply;
    JobType m_type;
    QByteArray m_call;
    QVariantList m_args;
};
#endif
