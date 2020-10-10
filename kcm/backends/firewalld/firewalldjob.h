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
