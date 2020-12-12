// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2020 Lucas Biaggi <lbjanuario@gmail.com>

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
#include <QProcess>

#include <loglistmodel.h>
#include <profile.h>
#include <rulelistmodel.h>

#include "firewalldclient.h"
#include "firewalldjob.h"
#include "firewalldlogmodel.h"

#include "systemdjob.h"

#include "dbustypes.h"

K_PLUGIN_CLASS_WITH_JSON(FirewalldClient, "firewalldbackend.json")
Q_LOGGING_CATEGORY(FirewallDClientDebug, "firewalld.client")

FirewalldClient::FirewalldClient(QObject *parent, const QVariantList &args)
    : IFirewallClientBackend(parent, args)
    , m_rulesModel(new RuleListModel(this))
{
    queryExecutable("firewalld");
    // HACK: Querrying the firewall status in this context
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
    return m_currentProfile.enabled();
}

KJob *FirewalldClient::setEnabled(const bool value)
{
    SystemdJob *job = new SystemdJob(static_cast<SYSTEMD::actions>(value));

    connect(job, &KJob::result, this, [this, job, value] {
        if (job->error()) {
            qCDebug(FirewallDClientDebug) << "Job Error: " << job->error() << job->errorString();
            return;
        }
        m_currentProfile.setEnabled(value);
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
        emit enabledChanged(value);
    });

    return job;
}

KJob *FirewalldClient::queryStatus(FirewallClient::DefaultDataBehavior defaultsBehavior, FirewallClient::ProfilesBehavior profilesBehavior)
{
    Q_UNUSED(defaultsBehavior);
    Q_UNUSED(profilesBehavior);

    FirewalldJob *job = new FirewalldJob("getAllRules");

    connect(job, &KJob::result, this, [this, job] {
        if (job->error()) {
            qCDebug(FirewallDClientDebug) << job->errorString();
            return;
        }
        qCDebug(FirewallDClientDebug) << job->name();
        const QVector<Rule*> rules = extractRulesFromResponse(job->get_firewalldreply());
        const QVariantMap args = {
            {"defaultIncomingPolicy", defaultIncomingPolicy()},
            {"defaultOutgoingPolicy", defaultOutgoingPolicy()},
            {"status", true}, {"ipv6Enabled", true}
        };
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

Rule *FirewalldClient::ruleAt(int index)
{
    auto rules = m_currentProfile.rules();

    if (index < 0 || index >= rules.count()) {
        return nullptr;
    }

    Rule *rule = rules.at(index);
    return rule;
}

KJob *FirewalldClient::addRule(Rule *rule)
{
    if (rule == nullptr) {
        qWarning() << "Invalid rule";
        return nullptr;
    }

    QVariantList dbusArgs = buildRule(rule);
    FirewalldJob *job = new FirewalldJob("addRule", dbusArgs);

    connect(job, &KJob::result, this, [this, job] {
        if (job->error()) {
            qCDebug(FirewallDClientDebug) << job->errorString() << job->error();
            return;
        }
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
    });

    job->start();
    return job;
}

KJob *FirewalldClient::removeRule(int index)
{
    QVariantList dbusArgs = buildRule(ruleAt(index));
    FirewalldJob *job = new FirewalldJob("removeRule", dbusArgs);

    connect(job, &KJob::result, this, [this, job] {
        if (job->error()) {
            qCDebug(FirewallDClientDebug) << job->errorString() << job->error();
            return;
        }
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
    });

    job->start();
    return job;
}

KJob *FirewalldClient::updateRule(Rule *ruleWrapper)
{
    if (ruleWrapper == nullptr) {
        qWarning() << "NULL rule";
        return nullptr;
    }
    KJob *addJob = addRule(ruleWrapper);
    KJob *removeJob = removeRule(ruleWrapper->position());
    connect(removeJob, &KJob::finished, this, [addJob, removeJob]() {
        if (removeJob->error()) {
            qCDebug(FirewallDClientDebug) << removeJob->errorString() << removeJob->error();
            return;
        }
        addJob->start();
    });

    return addJob;
}

KJob *FirewalldClient::moveRule(int from, int to)
{
    QVector<Rule*> rules = m_currentProfile.rules();
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

Rule *FirewalldClient::createRuleFromConnection(
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

    auto rule = new Rule();
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

    rule->setProtocol(knownProtocols().indexOf(protocol.toUpper()));
    return rule;
}

Rule *FirewalldClient::createRuleFromLog(
    const QString &protocol,
    const QString &sourceAddress,
    const QString &sourcePort,
    const QString &destinationAddress,
    const QString &destinationPort,
    const QString &inn)
{
    // Transform to the ufw notation
    auto rule = new Rule();

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

    rule->setProtocol(knownProtocols().indexOf(protocol.toUpper()));
    return rule;
}

void FirewalldClient::refreshProfiles()
{
}

bool FirewalldClient::isTcpAndUdp(int protocolIdx)
{
    Q_UNUSED(protocolIdx);
    return false;
}

QVariantList FirewalldClient::buildRule(const Rule *r) const
{
    QVariantMap args {
        {"priority", 0},
        {"destinationPort", r->destinationPort()},
        {"sourcePort", r->sourcePort()},
        {"type", QString(r->protocolSuffix(r->protocol())).replace("/", "")}, // tcp or udp
        {"destinationAddress", r->destinationAddress()},
        {"sourceAddress", r->sourceAddress()},
        {"interface_in", r->interfaceIn()},
        {"interface_out", r->interfaceOut()},
        {"table", "filter"},
    };

    args.insert("chain", r->incoming() ? "INPUT" : "OUTPUT");

    switch (r->action()) {
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
        firewalld_direct_rule << "-p" << value.toLower();
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

    value = args.value(args.value("chain") == "INPUT" ? "interface_in" : "interface_out").toString();
    if (!value.isEmpty() && !value.isNull()) {
        firewalld_direct_rule << "-i" << value;
    }

    QString ipvf = r->ipv6() == true ? "ipv6" : "ipv4";

    qCDebug(FirewallDClientDebug) << firewalld_direct_rule;
    return QVariantList({ipvf, args.value("table"), args.value("chain"), args.value("priority"), firewalld_direct_rule});
}

QString FirewalldClient::defaultIncomingPolicy() const
{
    auto policy_t = m_currentProfile.defaultIncomingPolicy();
    return Types::toString(policy_t);
};

QString FirewalldClient::defaultOutgoingPolicy() const
{
    auto policy_t = m_currentProfile.defaultOutgoingPolicy();
    return Types::toString(policy_t);
};

KJob *FirewalldClient::setDefaultIncomingPolicy(QString defaultIncomingPolicy)
{
    // fake job just to change default policy
    FirewalldJob *job = new FirewalldJob();
    connect(job, &KJob::result, this, [this, job, defaultIncomingPolicy] {
        if (job->error()) {
            qCDebug(FirewallDClientDebug) << job->errorString() << job->error();
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
            qCDebug(FirewallDClientDebug) << job->errorString() << job->error();
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
            qCDebug(FirewallDClientDebug) << job->name() << job->errorString() << job->error();
            return;
        }
        queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, FirewallClient::ProfilesBehavior::DontListenProfiles);
    });
    job->exec();
    return job;
};

LogListModel *FirewalldClient::logs()
{
    if (!m_logs) {
        m_logs = new FirewalldLogModel(this);
    }
    return m_logs;
}

QVector<Rule*> FirewalldClient::extractRulesFromResponse(const QList<firewalld_reply> &reply) const
{
    QVector<Rule*> message_rules;
    if (reply.size() <= 0) {
        return {};
    }

    for (auto r : reply) {
        const auto action = r.rules.at(
            r.rules.indexOf("-j") + 1) == "ACCEPT" ? Types::POLICY_ALLOW :
            r.rules.at(r.rules.indexOf("-j") + 1) == "REJECT" ? Types::POLICY_REJECT
            : Types::POLICY_DENY;

        const auto sourceAddress = r.rules.indexOf("-s") > 0 ? r.rules.at(r.rules.indexOf("-s") + 1) : "";
        const auto destinationAddress = r.rules.indexOf("-d") >= 0 ? r.rules.at(r.rules.indexOf("-d") + 1) : "";
        const auto interface_in = r.rules.indexOf("-i") >= 0 ? r.rules.at(r.rules.indexOf("-i") + 1) : "";
        const auto interface_out = r.rules.indexOf("-i") >= 0 ? r.rules.at(r.rules.indexOf("-i") + 1) : "";

        if (r.rules.indexOf("-p") < 0) {
            qWarning() << "Error forming rule";
        }

        const QString protocolName = r.rules.at(r.rules.indexOf("-p") + 1);
        const int protocolIdx = FirewallClient::knownProtocols().indexOf(protocolName);

        const int sourcePortIdx = r.rules.indexOf(QRegExp("^" + QRegExp::escape("--sport") + ".+"));
        const auto sourcePort = sourcePortIdx != -1 ? r.rules.at(sourcePortIdx).section("=", -1) : QStringLiteral("");
        const int destPortIdx = r.rules.indexOf(QRegExp("^" + QRegExp::escape("--dport") + ".+"));
        const auto destPort = destPortIdx != -1 ? r.rules.at(destPortIdx).section("=", -1) : QStringLiteral("");

        message_rules.push_back(
            new Rule(action,
                r.chain == "INPUT",
                Types::LOGGING_OFF,
                protocolIdx,
                sourceAddress,
                sourcePort,
                destinationAddress,
                destPort,
                r.chain == "INPUT" ? interface_in : "",
                r.chain == "OUTPUT" ? interface_out : "",
                "",
                "",
                r.priority,
                r.ipv == "ipv6"
            )
        );
    }

    return message_rules;
}

void FirewalldClient::setProfile(Profile profile)
{
    auto oldProfile = m_currentProfile;
    m_currentProfile = profile;
    m_rulesModel->setProfile(m_currentProfile);
    if (m_currentProfile.enabled() != oldProfile.enabled()) {
        emit enabledChanged(m_currentProfile.enabled());
    }

    if (m_currentProfile.defaultIncomingPolicy() != oldProfile.defaultIncomingPolicy()) {
        const QString policy = Types::toString(m_currentProfile.defaultIncomingPolicy());
        emit defaultIncomingPolicyChanged(policy);
    }

    if (m_currentProfile.defaultOutgoingPolicy() != oldProfile.defaultOutgoingPolicy()) {
        const QString policy = Types::toString(m_currentProfile.defaultOutgoingPolicy());
        emit defaultOutgoingPolicyChanged(policy);
    }
}

FirewallClient::Capabilities FirewalldClient::capabilities() const
{
    return FirewallClient::SaveCapability;
};

QStringList FirewalldClient::knownProtocols() {
    return {"TCP", "UDP"};
}

bool FirewalldClient::isCurrentlyLoaded() const
{
    QProcess process;
    const QString name = "systemctl";
    const QStringList args = {"status", "firewalld"};

    process.start(name, args);
    process.waitForFinished();

    // systemctl returns 0 for status if the app is loaded, and 3 otherwise.
    // systemctl returns 0 for status if the app is loaded, and 3 otherwise.
    qDebug() << "Firewalld is loaded?" << process.exitCode();

    return process.exitCode() == EXIT_SUCCESS;
}

#include "firewalldclient.moc"
