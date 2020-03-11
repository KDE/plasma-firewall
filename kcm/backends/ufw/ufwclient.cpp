/*
 * UFW KControl Module
 *
 * Copyright 2011 Craig Drummond <craig.p.drummond@gmail.com>
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
 * Copyright 2020 Tomaz Canabrava <tcanabrava@kde.org>
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


#include "ufwclient.h"

#include <QDebug>
#include <QTimer>
#include <QVariantMap>
#include <QNetworkInterface>
#include <QStandardPaths>
#include <QDir>

#include <KConfig>
#include <KLocalizedString>
#include <KConfigGroup>

// TODO: Figure out what's wrong with the registering
// REGISTER_BACKEND("ufw", UfwClient::createMethod);

namespace {
    void debugState(KAuth::Action::AuthStatus status) {
        using Status = KAuth::Action::AuthStatus;
        switch(status) {
            case Status::AuthorizedStatus: qDebug() << "Job Authorized"; break;
            case Status::AuthRequiredStatus: qDebug() << "Job Requires authentication"; break;
            case Status::UserCancelledStatus: qDebug() << "User cancelled!"; break;
            case Status::DeniedStatus: qDebug() << "Password denied"; break;
            case Status::InvalidStatus: qDebug() << "Invalid Status!"; break;
            case Status::ErrorStatus: qDebug() << "Job is in an error state"; break;
        }
    }
}

UfwClient::UfwClient(FirewallClient *parent) :
    IFirewallClientBackend(parent),
    m_rulesModel(new RuleListModel(this)),
    m_logs(new LogListModel(this))
{
    // HACK: Quering the firewall status in this context
    // creates a segmentation fault error in some situations
    // due to an usage of the rootObject before it's
    // initialization. So, it's delayed a little.
    //    refresh();
    QTimer::singleShot(100, this, &UfwClient::refresh);
    QTimer::singleShot(2000, this, &UfwClient::refreshLogs);
}

QString UfwClient::name() const
{
    return QStringLiteral("ufw");
}

void UfwClient::refresh()
{
    queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                FirewallClient::ProfilesBehavior::ListenProfiles);
}

bool UfwClient::enabled() const
{
    return m_currentProfile.getEnabled();
}

FirewallClient::Status UfwClient::status() const
{
    return m_status;
}

void UfwClient::setStatus(FirewallClient::Status status)
{
    if (m_status != status) {
        const bool oldBusy = busy();

        m_status = status;
        emit statusChanged(status);

        if (busy() != oldBusy) {
            emit busyChanged(busy());
        }
    }
}

void UfwClient::setEnabled(bool value)
{
    if (enabled() == value) {
        return;
    }

    setStatus(value ? FirewallClient::Enabling : FirewallClient::Disabling);

    QVariantMap args {
        {"cmd", "setStatus"},
        {"status", value},
    };

    KAuth::Action modifyAction = buildModifyAction(args);

    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, this, [this, job] {
        setStatus(FirewallClient::Idle);

        if (!job->error()) {
            queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                        FirewallClient::ProfilesBehavior::DontListenProfiles);
        } else {
            // User cancelled. returned error = 4.
            if (job->error() == 4) {
                //return; FIXME FIXME FIXME
            }
            emit showErrorMessage(i18n("Error setting the state of the firewall: %1", job->errorText()));
            emit enabledChanged(enabled());
        }
    });

    job->start();
}

void UfwClient::queryStatus(FirewallClient::DefaultDataBehavior defaultsBehavior, FirewallClient::ProfilesBehavior profilesBehavior)
{
    if (busy()) {
        qWarning() << "Ufw client is busy";
        return;
    }

    setStatus(FirewallClient::QueryingStatus);

    const bool readDefaults = defaultsBehavior == FirewallClient::DefaultDataBehavior::ReadDefaults;
    const bool listProfiles = profilesBehavior == FirewallClient::ProfilesBehavior::ListenProfiles;

    QVariantMap args {
        {"defaults", readDefaults},
        {"profiles", listProfiles},
    };

    if (m_queryAction.name().isEmpty()) {
        m_queryAction = buildQueryAction(args);
    }

    KAuth::ExecuteJob *job = m_queryAction.execute();
    connect(job, &KAuth::ExecuteJob::result, this, [this, job] {
        setStatus(FirewallClient::Idle);

        if (!job->error()) {
            QByteArray response = job->data().value("response", "").toByteArray();
            setProfile(Profile(response));
        } else {
            emit showErrorMessage(
                i18n("There was an error in the backend! Please report it.\n%1 %2",
                job->action().name(), job->errorString())
            );
            qWarning() << job->action().name() << job->errorString();
        }
    });

    job->start();
}

void UfwClient::setDefaultIncomingPolicy(QString policy)
{
    if (policy == defaultIncomingPolicy()) {
        return;
    }

    setStatus(FirewallClient::SettingDefaultIncomingPolicy);

    const QString xmlArg = QStringLiteral("<defaults incoming=\"%1\"/>").arg(policy);

    QVariantMap args {
        {"cmd","setDefaults"},
        {"xml", xmlArg},
    };

    KAuth::Action modifyAction = buildModifyAction(args);

    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, this, [this, job] {
        setStatus(FirewallClient::Idle);

        if (!job->error()) {
            queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                        FirewallClient::ProfilesBehavior::DontListenProfiles);
        } else {
            // User cancelled. returned error = 4.
            if (job->error() == 4) {
                return;
            }

            emit showErrorMessage(i18n("Error setting the firewall default incomming policy: %1", job->errorString()));
        }
    });

    job->start();
}

void UfwClient::setDefaultOutgoingPolicy(QString policy)
{
    if (policy == defaultOutgoingPolicy()) {
        return;
    }

    setStatus(FirewallClient::SettingDefaultOutgoingPolicy);

    const QString xmlArg = QStringLiteral("<defaults outgoing=\"%1\"/>").arg(policy);

    QVariantMap args {
        {"cmd", "setDefaults"},
        {"xml", xmlArg},
    };

    KAuth::Action modifyAction = buildModifyAction(args);

    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, this, [this, job] {
        setStatus(FirewallClient::Idle);

        if (!job->error()) {
            queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                        FirewallClient::ProfilesBehavior::DontListenProfiles);
        } else {
            // User cancelled. returned error = 4.
            if (job->error() == 4) {
                return;
            }

            emit showErrorMessage(i18n("Error setting the firewall default outcomming policy: %1", job->errorString()));
        }
    });

    job->start();
}

void UfwClient::setLogsAutoRefresh(bool logsAutoRefresh)
{
    if (m_logsAutoRefresh == logsAutoRefresh)
        return;

    if (logsAutoRefresh) {
        connect(&m_logsRefreshTimer, &QTimer::timeout, this, &UfwClient::refreshLogs);
        m_logsRefreshTimer.setInterval(3000);
        m_logsRefreshTimer.start();
    } else {
        disconnect(&m_logsRefreshTimer, &QTimer::timeout, this, &UfwClient::refreshLogs);
        m_logsRefreshTimer.stop();
    }

    m_logsAutoRefresh = logsAutoRefresh;
    emit logsAutoRefreshChanged(m_logsAutoRefresh);
}

void UfwClient::refreshLogs()
{
    //setStatus(FirewallClient::RefreshingLogs);

    KAuth::Action action("org.kde.ufw.viewlog");
    action.setHelperId("org.kde.ufw");

    QVariantMap args;
    if (m_rawLogs.size() > 0)
        args["lastLine"] = m_rawLogs.last();

    action.setArguments(args);

    KAuth::ExecuteJob *job = action.execute();
    connect(job, &KAuth::ExecuteJob::finished, this, [this, job] {
        //setStatus(FirewallClient::Idle);

        if (!job->error()) {
            QStringList newLogs = job->data().value("lines", "").toStringList();
            qDebug() << "NEW LOGS" << newLogs;
            m_rawLogs.append(newLogs);
            m_logs->addRawLogs(newLogs);
        } else {
            showErrorMessage(i18n("Error fetching firewall logs: %1", job->errorString()));
            qWarning() << "org.kde.ufw.viewlog" << job->errorString();
        }
    });

    job->start();
}

void UfwClient::setProfile(Profile profile)
{
    auto oldProfile = m_currentProfile;
    m_currentProfile = profile;

    m_rulesModel->setProfile(m_currentProfile);
    if (m_currentProfile.getEnabled() != oldProfile.getEnabled())
        emit enabledChanged(m_currentProfile.getEnabled());

    if (m_currentProfile.getDefaultIncomingPolicy() != oldProfile.getDefaultIncomingPolicy()) {
        const QString policy = Types::toString(m_currentProfile.getDefaultIncomingPolicy());
        emit defaultIncomingPolicyChanged(policy);
    }

    if (m_currentProfile.getDefaultOutgoingPolicy() != oldProfile.getDefaultOutgoingPolicy()) {
        const QString policy = Types::toString(m_currentProfile.getDefaultOutgoingPolicy());
        emit defaultOutgoingPolicyChanged(policy);
    }
}

KAuth::Action UfwClient::buildQueryAction(const QVariantMap &arguments)
{
    auto action = KAuth::Action("org.kde.ufw.query");
    action.setHelperId("org.kde.ufw");
    action.setArguments(arguments);

    return action;
}

KAuth::Action UfwClient::buildModifyAction(const QVariantMap &arguments)
{
    auto action = KAuth::Action("org.kde.ufw.modify");
    action.setHelperId("org.kde.ufw");
    action.setArguments(arguments);

    return action;
}

RuleListModel *UfwClient::rules() const
{
    return m_rulesModel;
}

RuleWrapper *UfwClient::getRule(int index)
{
    auto rules = m_currentProfile.getRules();

    if (index < 0 || index >= rules.count()) {
        return nullptr;
    }

    auto rule = rules.at(index);
    rule.setPosition(index);
    RuleWrapper * wrapper = new RuleWrapper(rule, this);

    return wrapper;
}

void UfwClient::addRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == nullptr) {
        qWarning() << "nullptr rule";
        return;
    }

    setStatus(FirewallClient::AddingRule);

    Rule rule = ruleWrapper->getRule();

    QVariantMap args {
        {"cmd", "addRules"},
        {"count",1},
        {"xml0", rule.toXml()},
    };

    KAuth::Action modifyAction = buildModifyAction(args);

    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, this, [this, job] {
        setStatus(FirewallClient::Idle);

        if (!job->error()) {
            queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                        FirewallClient::ProfilesBehavior::ListenProfiles);

            emit showSuccessMessage(i18n("Rule was created successfully."));
        } else {
            // User Cancelled the rule removal, returned error = 4.
            if (job->error() == 4) {
                return;
            }

            // TODO what about error code?
            showErrorMessage(i18n("Error creating the rule: %1", job->errorString()));

            qWarning() << job->action().name() << job->errorString();
        }
    });

    job->start();
}

void UfwClient::removeRule(int index)
{
    if (index < 0 || index >= m_currentProfile.getRules().count()) {
        qWarning() << __FUNCTION__ << "invalid rule index";
        return;
    }

    setStatus(FirewallClient::RemovingRule);

    // Correct index
    index += 1;

    QVariantMap args {
        {"cmd", "removeRule"},
        {"index", QString::number(index)},
    };

    KAuth::Action modifyAction = buildModifyAction(args);
    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::statusChanged, this, [this] (KAuth::Action::AuthStatus status) {
        debugState(status);
    });

    connect(job, &KAuth::ExecuteJob::result, this, [this, job] {
        setStatus(FirewallClient::Idle);

        if (!job->error()) {
            queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                        FirewallClient::ProfilesBehavior::ListenProfiles);
        } else {
            // User Cancelled the rule removal, returned error = 4.
            if (job->error() == 4) {
                return;
            }

            emit showErrorMessage(i18n("Error removing rule: %1", job->errorText()));
            qWarning() << job->action().name() << job->errorString();
        }
    });

    job->start();
}

void UfwClient::updateRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == nullptr) {
        qWarning() <<  "nullptr rule";
        return;
    }

    setStatus(FirewallClient::UpdatingRule);

    Rule rule = ruleWrapper->getRule();

    rule.setPosition(rule.getPosition() + 1);
    QVariantMap args {
        {"cmd", "editRule"},
        {"xml", rule.toXml()},
    };

    KAuth::Action modifyAction = buildModifyAction(args);
    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, this, [this, job] {
        setStatus(FirewallClient::Idle);

        if (!job->error()) {
            queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                        FirewallClient::ProfilesBehavior::ListenProfiles);
        } else {
            // User Cancelled the rule edition, returned error = 4.
            if (job->error() == 4) {
                return;
            }

            emit showErrorMessage(i18n("Error updating rule: %1", job->errorString()));
            qWarning() << job->action().name() << job->errorString();
        }
    });

    job->start();
}

void UfwClient::moveRule(int from, int to)
{
    const QVector<Rule> rules = m_currentProfile.getRules();
    if (from < 0 || from >= rules.count()) {
        qWarning() << "invalid from index";
        return;
    }

    if (to < 0 || to >= rules.count()) {
        qWarning() << "invalid to index";
        return;
    }

    setStatus(FirewallClient::MovingRule);

    // Correct indices
    from += 1;
    to += 1;

    QVariantMap args {
        {"cmd", "moveRule"},
        {"from", from},
        {"to", to},
    };

    KAuth::Action modifyAction = buildModifyAction(args);
    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::finished, this, [this, job] {
        setStatus(FirewallClient::Idle);

        if (!job->error()) {
            queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults,
                        FirewallClient::ProfilesBehavior::ListenProfiles);
        } else {
            // User cancelled. returned error = 4.
            if (job->error() == 4) {
                return;
            }

            emit showErrorMessage(i18n("Error moving rule: %1", job->errorString()));

            qWarning() << job->action().name() << job->errorString();
        }
    });

    job->start();
}

QString UfwClient::defaultIncomingPolicy() const
{
    auto policy_t = m_currentProfile.getDefaultIncomingPolicy();
    return Types::toString(policy_t);
}

QString UfwClient::defaultOutgoingPolicy() const
{
    auto policy_t = m_currentProfile.getDefaultOutgoingPolicy();
    return Types::toString(policy_t);
}

LogListModel *UfwClient::logs()
{
    return m_logs;
}


bool UfwClient::logsAutoRefresh() const
{
    return m_logsAutoRefresh;
}

RuleWrapper* UfwClient::createRuleFromConnection(const QString &protocol, const QString &localAddress, const QString &foreignAddres, const QString &status)
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

RuleWrapper *UfwClient::createRuleFromLog(
    const QString &protocol,
    const QString &sourceAddress,
    const QString &sourcePort,
    const QString &destinationAddress,
    const QString &destinationPort,
    const QString &inn)
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

IFirewallClientBackend* UfwClient::createMethod(FirewallClient* parent)
{
    IFirewallClientBackend *instance = new UfwClient(parent);
    return instance;
}

bool UfwClient::hasExecutable() const {
     return !QStandardPaths::findExecutable("ufw").isEmpty();
}
 
// FIXME is this even used?
void UfwClient::setExecutable(const bool &hasExecutable){
    emit hasExecutableChanged(hasExecutable);
}

void UfwClient::refreshProfiles()
{

    static const char * constProfileDir="/etc/ufw/applications.d/";

    const QStringList files(QDir(constProfileDir).entryList(QDir::NoDotAndDotDot));

    QVector<Entry> profiles;
    for (const auto &file : files) {
        KConfig cfg(constProfileDir + file, KConfig::SimpleConfig);

        for(const auto group : cfg.groupList()) {
            const QString ports(cfg.group(group).readEntry("ports", QString()));

            if(!ports.isEmpty() && !profiles.contains(group))
                profiles.append(Entry(group, ports));
        }
    }

    setProfiles(profiles);
}
