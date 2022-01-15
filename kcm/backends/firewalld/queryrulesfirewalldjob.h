// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2022 Lucas Biaggi <lbjanuario@gmail.com>
/*
 * Firewalld backend for plasma firewall
 */
#ifndef QUERYRULESFIREWALLDJOB_H
#define QUERYRULESFIREWALLDJOB_H

#include "firewalldjob.h"

class QueryRulesFirewalldJob : public FirewalldJob
{
    Q_OBJECT

public:
    QueryRulesFirewalldJob();
    ~QueryRulesFirewalldJob();

    void start() override;
    QList<firewalld_reply> getFirewalldreply() override;
    QStringList getServices() override;
    QString name();
    Q_SIGNAL void finished();

private:
    FirewalldJob *m_direct;
    FirewalldJob *m_simple;
    bool m_directFinished = false;
    bool m_simpleFinished = false;
};

#endif
