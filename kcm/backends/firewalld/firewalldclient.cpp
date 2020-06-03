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

#include <KConfigGroup>
#include <KLocalizedString>
#include <KPluginFactory>

#include <QDBusMetaType>
#include <QDebug>
#include <QDir>
#include <QNetworkInterface>
#include <QStandardPaths>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include <loglistmodel.h>
#include <profile.h>
#include <rulelistmodel.h>
#include <rulewrapper.h>

#include "firewalldclient.h"
#include "firewalldjob.h"
#include "systemdjob.h"

#include "dbustypes.h"

K_PLUGIN_CLASS_WITH_JSON(FirewalldClient, "firewalldbackend.json")

FirewalldClient::FirewalldClient(QObject *parent, const QVariantList &args)
    : IFirewallClientBackend(parent, args)
    , m_rulesModel(new RuleListModel(this))
{
    // HACK: Quering the firewall status in this context
    // creates a segmentation fault error in some situations
    // due to an usage of the rootObject before it's
    // initialization. So, it's delayed a little.
    //    refresh();
    QTimer::singleShot(1, this, &FirewalldClient::refresh);
    qDBusRegisterMetaType<firewalld_reply>();
    qDBusRegisterMetaType<QList<firewalld_reply>>();
}

QString FirewalldClient::name() const
{
    return QStringLiteral("firewalld");
}

void FirewalldClient::refresh()
{
    queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::ListenProfiles);
}

bool FirewalldClient::enabled() const
{
    return m_currentProfile.getEnabled();
}
KJob *FirewalldClient::setEnabled(const bool value)
{
    SystemdJob *job = new SystemdJob(static_cast<SYSTEMD::actions>(value));

    connect(job, &KJob::result, this, [this, job, value] {
        if (job->error()) {
            qDebug() << "Job Error: " << job->error() << job->errorString();
            return;
        }
        m_currentProfile.setEnabled(value);
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
        emit enabledChanged(value);
    });

    job->start();
    return job;
}

KJob *FirewalldClient::queryStatus(FirewallClient::DefaultDataBehavior defaultsBehavior, FirewallClient::ProfilesBehavior profilesBehavior)
{
    FirewalldJob *job = new FirewalldJob("getAllRules");

    connect(job, &KJob::result, this, [this, job] {
        if (job->error()) {
            qDebug() << job->errorString();
            return;
        }
        qDebug() << job->name();
        const QVector<Rule> rules = extractRulesFromResponse(job->get_firewalldreply());
        const QVariantMap args = {{"defaultIncomingPolicy", defaultIncomingPolicy()}, {"defaultOutgoingPolicy", defaultOutgoingPolicy()}, {"status", true}, {"ipv6Enabled", true}};
        setProfile(Profile(rules, args));
    });
    job->start();
    return job;
}

void FirewalldClient::setLogsAutoRefresh(bool logsAutoRefresh)
{
    if (m_logsAutoRefresh == logsAutoRefresh) {
        return;
    }

    if (logsAutoRefresh) {
        connect(&m_logsRefreshTimer, &QTimer::timeout, this, &FirewalldClient::refreshLogs);
        m_logsRefreshTimer.setInterval(3000);
        m_logsRefreshTimer.start();
    } else {
        disconnect(&m_logsRefreshTimer, &QTimer::timeout, this, &FirewalldClient::refreshLogs);
        m_logsRefreshTimer.stop();
    }

    m_logsAutoRefresh = logsAutoRefresh;
    emit logsAutoRefreshChanged(m_logsAutoRefresh);
}

void FirewalldClient::refreshLogs() {};

RuleListModel *FirewalldClient::rules() const
{
    return m_rulesModel;
}

RuleWrapper *FirewalldClient::getRule(int index)
{
    auto rules = m_currentProfile.getRules();

    if (index < 0 || index >= rules.count()) {
        return NULL;
    }

    auto rule = rules.at(index);
    rule.setPosition(index);

    return new RuleWrapper(rule, this);
}

KJob *FirewalldClient::addRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == nullptr) {
        qWarning() << "Invalid rule";
        return;
    }

    QVariantList dbusArgs = buildRule(ruleWrapper->getRule());
    FirewalldJob *job = new FirewalldJob("addRule", dbusArgs);

    connect(job, &KJob::result, this, [this, job] {
        if (job->error()) {
            qDebug() << job->errorString() << job->error();
            return;
        }
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
    });

    job->start();
    return job;
}

KJob *FirewalldClient::removeRule(int index)
{
    QVariantList dbusArgs = buildRule(getRule(index)->getRule());
    FirewalldJob *job = new FirewalldJob("removeRule", dbusArgs);

    connect(job, &KJob::result, this, [this, job] {
        if (job->error()) {
            qDebug() << job->errorString() << job->error();
            return;
        }
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
    });

    job->start();
    return job;
}

KJob *FirewalldClient::updateRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == NULL) {
        qWarning() << "NULL rule";
    }
    KJob *addJob = addRule(ruleWrapper);
    KJob *removeJob = removeRule(ruleWrapper->position());
    connect(removeJob, &KJob::finished, this, [addJob, removeJob]() {
        if (removeJob->error()) {
            qDebug() << removeJob->errorString() << removeJob->error();
            return;
        }
        addJob->start();
    });

    return addJob;
}

KJob *FirewalldClient::moveRule(int from, int to)
{
    QVector<Rule> rules = m_currentProfile.getRules();
    if (from < 0 || from >= rules.count()) {
        qWarning() << "invalid from index";
    }

    if (to < 0 || to >= rules.count()) {
        qWarning() << "invalid to index";
    }
    // Correct indices
    from += 1;
    to += 1;

    QVariantMap args {
        {"cmd", "moveRule"},
        {"from", from},
        {"to", to},
    };

    return new FirewalldJob();
}

bool FirewalldClient::logsAutoRefresh() const
{
    return m_logsAutoRefresh;
}

RuleWrapper *FirewalldClient::createRuleFromConnection(const QString &protocol, const QString &localAddress, const QString &foreignAddres, const QString &status)
{
    auto _localAddress = localAddress;
    _localAddress.replace("*", "");
    _localAddress.replace("0.0.0.0", "");

    auto _foreignAddres = foreignAddres;
    _foreignAddres.replace("*", "");
    _foreignAddres.replace("0.0.0.0", "");

    auto localAddressData = _localAddress.split(":");
    auto foreignAddresData = _foreignAddres.split(":");

    auto rule = new RuleWrapper({});
    rule->setIncoming(status == QStringLiteral("LISTEN"));
    rule->setPolicy("deny");

    // Prepare rule draft
    if (status == QStringLiteral("LISTEN")) {
        rule->setSourceAddress(foreignAddresData[0]);
        rule->setSourcePort(foreignAddresData[1]);
        rule->setDestinationAddress(localAddressData[0]);
        rule->setDestinationPort(localAddressData[1]);
    } else {
        rule->setSourceAddress(localAddressData[0]);
        rule->setSourcePort(localAddressData[1]);
        rule->setDestinationAddress(foreignAddresData[0]);
        rule->setDestinationPort(foreignAddresData[1]);
    }

    rule->setProtocol(FirewallClient::getKnownProtocols().indexOf(protocol.toUpper()));
    return rule;
}

RuleWrapper *FirewalldClient::createRuleFromLog(const QString &protocol, const QString &sourceAddress, const QString &sourcePort, const QString &destinationAddress, const QString &destinationPort, const QString &inn)
{
    // Transform to the ufw notation
    auto rule = new RuleWrapper({});

    auto _sourceAddress = sourceAddress;
    _sourceAddress.replace("*", "");
    _sourceAddress.replace("0.0.0.0", "");

    auto _destinationAddress = destinationAddress;
    _destinationAddress.replace("*", "");
    _destinationAddress.replace("0.0.0.0", "");

    // Prepare rule draft
    rule->setIncoming(inn.size());
    rule->setPolicy("allow");
    rule->setSourceAddress(_sourceAddress);
    rule->setSourcePort(sourcePort);

    rule->setDestinationAddress(_destinationAddress);
    rule->setDestinationPort(destinationPort);

    rule->setProtocol(FirewallClient::getKnownProtocols().indexOf(protocol.toUpper()));
    return rule;
}

bool FirewalldClient::hasExecutable() const
{
    return !QStandardPaths::findExecutable("firewalld").isEmpty();
}

void FirewalldClient::setExecutable(const bool &hasExecutable)
{
    emit hasExecutableChanged(hasExecutable);
}

void FirewalldClient::refreshProfiles()
{
}

QVariantList FirewalldClient::buildRule(Rule r, FirewallClient::Ipv ipvfamily) const
{
    QVariantMap args {
        {"priority", 0},
        {"destinationPort", r.getDestPort()},
        {"sourcePort", r.getSourcePort()},
        {"type", QString(r.protocolSuffix(r.getProtocol())).replace("/", "")}, // tcp or udp
        {"destinationAddress", r.getDestAddress()},
        {"sourceAddress", r.getSourceAddress()},
        {"interface_in", r.getInterfaceIn()},
        {"interface_out", r.getInterfaceOut()},
        {"table", "filter"},
    };

    args.insert("chain", r.getIncoming() ? "INPUT" : "OUTPUT");

    switch (r.getAction()) {
    case Types::POLICY_ALLOW:
        args.insert("action", "ACCEPT");
        break;
    case Types::POLICY_REJECT:
        args.insert("action", "REJECT");
        break;
    default:
        args.insert("action", "DROP");
    }

    QStringList firewalld_direct_rule = {"-j", args.value("action").toString()};
    auto value = args.value("type").toString();
    if (!value.isEmpty()) {
        firewalld_direct_rule << "-p" << value;
    }

    value = args.value("destinationAddress").toString();
    if (!value.isEmpty()) {
        firewalld_direct_rule << "-d" << value;
    }

    value = args.value("destinationPort").toString();
    if (!value.isEmpty()) {
        firewalld_direct_rule << "--dport=" + value;
    }

    value = args.value("sourceAddress").toString();
    if (!value.isEmpty()) {
        firewalld_direct_rule << "-s" << value;
    }

    value = args.value("sourcePort").toString();
    if (!value.isEmpty()) {
        firewalld_direct_rule << "--sport=" + value;
    }

    if (args.value("chain") == "INPUT") {
        value = args.value("interface_in").toString();
        if (!value.isEmpty() && !value.isNull())
            firewalld_direct_rule << "-i" << value;
    } else {
        value = args.value("interface_out").toString();
        if (!value.isEmpty() && !value.isNull())
            firewalld_direct_rule << "-i" << value;
    }

    auto ipvf = ipvfamily == FirewallClient::IPV6 ? "ipv6" : "ipv4";

    qDebug() << firewalld_direct_rule;
    return QVariantList({ipvf, args.value("table").toString(), args.value("chain").toString(), args.value("priority").toInt(), firewalld_direct_rule});
}
QString FirewalldClient::defaultIncomingPolicy() const
{
    auto policy_t = m_currentProfile.getDefaultIncomingPolicy();
    return Types::toString(policy_t);
};
QString FirewalldClient::defaultOutgoingPolicy() const
{
    auto policy_t = m_currentProfile.getDefaultOutgoingPolicy();
    return Types::toString(policy_t);
};

KJob *FirewalldClient::setDefaultIncomingPolicy(QString defaultIncomingPolicy)
{
    // fake job just to change default policy
    FirewalldJob *job = new FirewalldJob();
    connect(job, &KJob::result, this, [this, job, defaultIncomingPolicy] {
        if (job->error()) {
            qDebug() << job->errorString() << job->error();
            return;
        }
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
        m_currentProfile.setDefaultIncomingPolicy(defaultIncomingPolicy);
    });

    job->start();
    return job;
};

KJob *FirewalldClient::setDefaultOutgoingPolicy(QString defaultOutgoingPolicy)
{
    // fake job just to change default policy
    FirewalldJob *job = new FirewalldJob();
    connect(job, &KJob::result, this, [this, job, defaultOutgoingPolicy] {
        if (job->error()) {
            qDebug() << job->errorString() << job->error();
            return;
        }
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
        m_currentProfile.setDefaultIncomingPolicy(defaultOutgoingPolicy);
    });

    job->start();
    return job;
};

KJob *FirewalldClient::save()
{
    // fake job just to change default policy
    FirewalldJob *job = new FirewalldJob(FirewalldJob::SAVEFIREWALLD);

    connect(job, &KJob::result, this, [this, job] {
        if (job->error()) {
            qDebug() << job->name() << job->errorString() << job->error();
            return;
        }
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
    });
    job->exec();
    return job;
};

LogListModel *FirewalldClient::logs()
{
    return m_logs;
}

QVector<Rule> FirewalldClient::extractRulesFromResponse(const QList<firewalld_reply> &reply) const
{
    QVector<Rule> message_rules;
    if (reply.size() > 0) {
        for (auto r : reply) {
            const auto action = r.rules.at(r.rules.indexOf("-j") + 1) == "ACCEPT" ? Types::POLICY_ALLOW : r.rules.at(r.rules.indexOf("-j") + 1) == "REJECT" ? Types::POLICY_REJECT : Types::POLICY_DENY;

            const auto sourceAddress = r.rules.indexOf("-s") > 0 ? r.rules.at(r.rules.indexOf("-s") + 1) : "";
            const auto destinationAddress = r.rules.indexOf("-d") >= 0 ? r.rules.at(r.rules.indexOf("-d") + 1) : "";
            const auto protocol = r.rules.indexOf("-p") >= 0 ? Types::toProtocol(r.rules.at(r.rules.indexOf("-p") + 1)) : Types::PROTO_BOTH;
            const auto interface_in = r.rules.indexOf("-i") >= 0 ? r.rules.at(r.rules.indexOf("-i") + 1) : "";
            const auto interface_out = r.rules.indexOf("-i") >= 0 ? r.rules.at(r.rules.indexOf("-i") + 1) : "";

            const auto sourcePort = r.rules.at(r.rules.indexOf(QRegExp("^" + QRegExp::escape("--sport") + ".+"))).section("=", -1);
            const auto destPort = r.rules.at(r.rules.indexOf(QRegExp("^" + QRegExp::escape("--dport") + ".+"))).section("=", -1);
            qDebug() << r.ipv << r.chain << r.table << r.priority << r.rules;
            message_rules.push_back(Rule(action,
                                         r.chain == "INPUT",
                                         Types::LOGGING_OFF,
                                         protocol,
                                         sourceAddress,
                                         sourcePort,
                                         destinationAddress,
                                         destPort,
                                         r.chain == "INPUT" ? interface_in : "",
                                         r.chain == "OUTPUT" ? interface_out : "",
                                         "",
                                         "",
                                         r.priority,
                                         r.ipv == "ipv6"));
        }
    }
    return message_rules;
}

void FirewalldClient::setProfile(Profile profile)
{
    auto oldProfile = m_currentProfile;
    m_currentProfile = profile;
    m_rulesModel->setProfile(m_currentProfile);
    if (m_currentProfile.getEnabled() != oldProfile.getEnabled()) {
        emit enabledChanged(m_currentProfile.getEnabled());
    }

    if (m_currentProfile.getDefaultIncomingPolicy() != oldProfile.getDefaultIncomingPolicy()) {
        const QString policy = Types::toString(m_currentProfile.getDefaultIncomingPolicy());
        emit defaultIncomingPolicyChanged(policy);
    }

    if (m_currentProfile.getDefaultOutgoingPolicy() != oldProfile.getDefaultOutgoingPolicy()) {
        const QString policy = Types::toString(m_currentProfile.getDefaultOutgoingPolicy());
        emit defaultOutgoingPolicyChanged(policy);
    }
}

FirewallClient::Capabilities FirewalldClient::capabilities() const
{
    return FirewallClient::SaveCapability;
};
#include "firewalldclient.moc"
