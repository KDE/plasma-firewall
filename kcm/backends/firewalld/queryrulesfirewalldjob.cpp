// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2022 Lucas Biaggi <lbjanuario@gmail.com>
/*
 * Firewalld backend for plasma firewall
 */
#include "queryrulesfirewalldjob.h"
#include <KLocalizedString>

QueryRulesFirewalldJob::QueryRulesFirewalldJob()
{
    m_simple = new FirewalldJob("getServices", {""}, FirewalldJob::SIMPLELIST);
    m_direct = new FirewalldJob("getAllRules");

    connect(m_direct, &KJob::result, this, [this](void) {
        m_directFinished = true;
        if (m_simpleFinished) {
            emit finished();
        }
    });

    connect(m_simple, &KJob::result, this, [this](void) {
        m_simpleFinished = true;
        if (m_directFinished) {
            emit finished();
        }
    });
}

QString QueryRulesFirewalldJob::name()
{
    return i18n("firewalld listing rules and services");
}

QList<firewalld_reply> QueryRulesFirewalldJob::getFirewalldreply()
{
    if (m_direct == nullptr) {
        return {};
    }
    return m_direct->getFirewalldreply();
}

QStringList QueryRulesFirewalldJob::getServices()
{
    if (m_simple == nullptr) {
        return {};
    }
    return m_simple->getServices();
}

void QueryRulesFirewalldJob::start()
{
    m_direct->start();
    m_simple->start();
    return;
}

QueryRulesFirewalldJob::~QueryRulesFirewalldJob() = default;
