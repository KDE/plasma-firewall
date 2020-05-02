/*
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License or (at your option) version 3 or any later version
 * accepted by the membership of KDE e.V. (or its successor approved
 * by the membership of KDE e.V.), which shall act as a proxy
 * defined in Section 14 of version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "firewalldclient.h"
#include "firewalldjob.h"

#include <QDebug>
#include <QTimer>
#include <QVariantMap>
#include <QNetworkInterface>
#include <QStandardPaths>
#include <QDir>
#include <KLocalizedString>
#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusMessage>
#include <QVariantList>
#include <KConfigGroup>
#include <KPluginFactory>
#include <KLocalizedString>


#include <rulewrapper.h>
#include <rulelistmodel.h>
#include <loglistmodel.h>

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
}


QString FirewalldClient::name() const
{
    return QStringLiteral("firewalld");
}

void FirewalldClient::refresh()
{
    queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, 
            FirewallClient::ProfilesBehavior::ListenProfiles);
}

bool FirewalldClient::enabled() const
{
    return m_serviceStatus;
}
KJob *FirewalldClient::setEnabled(const bool value)
{

    FirewalldJob *job = new FirewalldJob(static_cast<SYSTEMD::actions>(value));
    if (m_serviceStatus != value) {
        m_serviceStatus = static_cast<SYSTEMD::actions>(value);
        QTimer::singleShot(500, this, [this] { emit enabledChanged(true); });
    }
    job->start();
    return job;

}

KJob *FirewalldClient::queryStatus(FirewallClient::DefaultDataBehavior defaultsBehavior, 
        FirewallClient::ProfilesBehavior profilesBehavior) {
    
    FirewalldJob *job = new FirewalldJob("getAllRules");    
    
     connect(job, &KJob::result, this, [job] {
        if (!job->error()) {
            qDebug() << job->name();
            for (auto x: job->get_firewalldreply())
                qDebug() << x.rules;
        } else {
            qDebug() << job->errorString();
        }
    });
    job->start();
    return job;
}


void FirewalldClient::setLogsAutoRefresh(bool logsAutoRefresh)
{
    if (m_logsAutoRefresh == logsAutoRefresh)
        return;

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
    RuleWrapper *wrapper = new RuleWrapper(rule, this);

    return wrapper;
}

KJob  *FirewalldClient::addRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == NULL) {
        qWarning() << "NULL rule";
    }
    QVariantList dbusArgs = buildRule(ruleWrapper->getRule());
    FirewalldJob *job = new FirewalldJob("addRule", dbusArgs);
    job->start();
    connect(job, &KJob::result, this, [this, job] {
        if (!job->error()) {
            queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                        FirewallClient::ProfilesBehavior::DontListenProfiles);
        }
        else
            qDebug() << job->errorString() << job->error();
        
    });
    return job;
   
}

KJob *FirewalldClient::removeRule(int index)
{
    QVariantList dbusArgs = buildRule(getRule(index)->getRule());
    FirewalldJob *job = new FirewalldJob("removeRule", dbusArgs);
    job->start();
    return job;
}

KJob *FirewalldClient::updateRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == NULL) {
        qWarning() << "NULL rule";
    }
    auto action = removeRule(ruleWrapper->position());
    action = addRule(ruleWrapper);
    return action;
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
    
    FirewalldJob *job = new FirewalldJob();
    return job;
}

bool FirewalldClient::logsAutoRefresh() const
{
    return m_logsAutoRefresh;
}

RuleWrapper *FirewalldClient::createRuleFromConnection(
    const QString &protocol, 
    const QString &localAddress, 
    const QString &foreignAddres, 
    const QString &status)
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

RuleWrapper *FirewalldClient::createRuleFromLog(
        const QString &protocol,
        const QString &sourceAddress,
        const QString &sourcePort,
        const QString &destinationAddress,
        const QString &destinationPort,
        const QString &inn
        )
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



QVariantList FirewalldClient::buildRule(Rule r, FirewallClient::Ipv ipvfamily)
{
    QVariantMap args {
        {"priority", r.getPosition()},
            {"destinationPort", r.getDestPort()},
            {"sourcePort", r.getSourcePort()},
            {"type", QString(r.protocolSuffix(r.getProtocol())).replace("/", "")}, // tcp or udp
            {"destinationAddress", r.getDestAddress()},
            {"sourceAddress", r.getSourceAddress()},
            {"table", "filter"}

    };

    args.insert("chain",  r.getIncoming() ? "INPUT" : "OUTPUT");

    switch(r.getAction()){
    case Types::POLICY_ALLOW:
        args.insert("action", "ACCEPT");
        break;
    case Types::POLICY_REJECT:
        args.insert("action", "REJECT");
        break;
    default:
        args.insert("action", "DROP");
    }

    QStringList firewalld_direct_rule = {"-p", args.value("type").toString(), "-j",
        args.value("action").toString()
    };

    auto value = args.value("destinationAddress").toString();
    if (!value.isEmpty())
        firewalld_direct_rule << "-d" <<  value;

    value = args.value("destinationPort").toString();
    if (!value.isEmpty())
        firewalld_direct_rule << "--dport=" +  value;

    value = args.value("sourceAddress").toString();
    if (!value.isEmpty())
        firewalld_direct_rule << "-s" <<  value;

    value = args.value("sourcePort").toString();
    if (!value.isEmpty())
        firewalld_direct_rule << "--sport=" +  value;

    auto ipvf = ipvfamily == FirewallClient::IPV6 ? "ipv6" : "ipv4";

    qDebug() << firewalld_direct_rule;
    return QVariantList({ipvf, args.value("table").toString(),
                args.value("chain").toString(), args.value("priority").toInt(), firewalld_direct_rule
                });

}
QString FirewalldClient::defaultIncomingPolicy() const {return "test";};
QString FirewalldClient::defaultOutgoingPolicy() const {return "test";};

KJob* FirewalldClient::setDefaultIncomingPolicy(QString defaultIncomingPolicy) {
    
    FirewalldJob *job = new FirewalldJob();
    return job;
};
KJob* FirewalldClient::setDefaultOutgoingPolicy(QString defaultOutgoingPolicy) {
    FirewalldJob *job = new FirewalldJob();
    return job;
};


LogListModel *FirewalldClient::logs()
{
    return m_logs;
}




#include "firewalldclient.moc"
