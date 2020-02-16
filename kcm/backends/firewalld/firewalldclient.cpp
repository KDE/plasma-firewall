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

#include <QDebug>
#include <QTimer>
#include <QVariantMap>
#include <QNetworkInterface>
#include <QStandardPaths>
#include <QDir>
#include <KConfig>
#include <KLocalizedString>
#include <KConfigGroup>
#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>

const QDBusArgument &operator>>(const QDBusArgument &argument, firewalld_reply &mystruct)
{
    argument.beginStructure();
    argument >> mystruct.ipv >> mystruct.table >> mystruct.chain >> mystruct.priority >> mystruct.rules;
    argument.endStructure();
    return argument;
}



FirewalldClient::FirewalldClient(FirewallClient *parent) :
    IFirewallClientBackend(parent),
    m_isBusy(false),
    m_rulesModel(new RuleListModel(this)),
    m_logs(new LogListModel(this))
{
   
    QTimer::singleShot(100, this, &FirewalldClient::refresh);
    QTimer::singleShot(2000, this, &FirewalldClient::refreshLogs);
}

QString FirewalldClient::name() const
{
    return QStringLiteral("firewalld");
}

void FirewalldClient::refresh()
{
    queryStatus();
}

bool FirewalldClient::enabled() const
{
    return m_currentProfile.getEnabled();
}

void FirewalldClient::setEnabled(bool enabled)
{
    QVariantMap args {
        {"cmd", "setStatus"},
        {"status", enabled},
    };

    KAuth::Action modifyAction = buildModifyAction(args);

    m_status = enabled ? i18n("Enabling the firewall...") : i18n("Disabling the firewall...");
    m_isBusy = true;


    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);
        setBusy(false);

        if (!job->error())
            queryStatus(true, false);


    });

    job->start();
}


bool FirewalldClient::isBusy() const
{
    return m_isBusy;
}

void FirewalldClient::queryStatus(bool readDefaults, bool listProfiles)
{
    if (isBusy())
    {
        qWarning() << "Ufw client is busy";
        return;
    }

    QVariantMap args {
        {"defaults", readDefaults},
        {"profiles", listProfiles},
    };

    if (m_queryAction.name().isEmpty()) {
        m_queryAction = buildQueryAction(args);
    }

    KAuth::ExecuteJob *job = m_queryAction.execute();
    connect(job, &KAuth::ExecuteJob::result, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);

        if (!job->error())
        {
            QByteArray response = job->data().value("response", "").toByteArray();
            setProfile(Profile(response));
        } else {
            setStatus(
                QStringLiteral("There was an error in the backend! Please report it. \n") +
                job->action().name() + QStringLiteral(" ") + job->errorString()
            );
            qWarning() << job->action().name() << job->errorString();
        }

        setBusy(false);
    });

    job->start();
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
    emit parentClient()->logsAutoRefreshChanged(m_logsAutoRefresh);
}

void FirewalldClient::refreshLogs()
{
    KAuth::Action action("org.kde.ufw.viewlog");
    action.setHelperId("org.kde.ufw");

    QVariantMap args;
    if (m_rawLogs.size() > 0)
        args["lastLine"] = m_rawLogs.last();

    action.setArguments(args);

    KAuth::ExecuteJob *job = action.execute();
    connect(job, &KAuth::ExecuteJob::finished, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);

        if (!job->error())
        {
            QStringList newLogs = job->data().value("lines", "").toStringList();
            m_rawLogs.append(newLogs);
            m_logs->addRawLogs(newLogs);
        } else {
            qWarning() << "org.kde.ufw.viewlog" << job->errorString();
        }
        setBusy(false);
    });

    job->start();
}

void FirewalldClient::setStatus(const QString &status)
{
    m_status = status;
    emit parentClient()->statusChanged(m_status);
}

void FirewalldClient::setBusy(const bool &isBusy)
{
    if (m_isBusy != isBusy)
    {
        m_isBusy = isBusy;
        emit parentClient()->isBusyChanged(isBusy);
    }
}


KAuth::Action FirewalldClient::buildQueryAction(const QVariantMap &arguments)
{
    auto action = KAuth::Action("org.kde.ufw.query");
    action.setHelperId("org.kde.ufw");
    action.setArguments(arguments);

    return action;
}

KAuth::Action FirewalldClient::buildModifyAction(const QVariantMap &arguments)
{
    auto action = KAuth::Action("org.kde.ufw.modify");
    action.setHelperId("org.kde.ufw");
    action.setArguments(arguments);

    return action;
}

QString FirewalldClient::status() const
{
    return m_status;
}

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
    RuleWrapper * wrapper = new RuleWrapper(rule, this);

    return wrapper;
}

void FirewalldClient::addRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == NULL) {
        qWarning() << __FUNCTION__ << "NULL rule";
        return;
    }

    Rule rule = ruleWrapper->getRule();

    QVariantMap args {
        {"cmd", "addRules"},
        {"count",1},
        {"xml0", rule.toXml()},
    };

    KAuth::Action modifyAction = buildModifyAction(args);

    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);

        if (!job->error())
        {
            QByteArray response = job->data().value("response", "").toByteArray();
            setProfile(Profile(response));
        } else {
            qWarning() << job->action().name() << job->errorString();
        }
        setBusy(false);
    });

    job->start();
}

void FirewalldClient::removeRule(int index)
{
    if (index < 0 || index >= m_currentProfile.getRules().count()) {
        qWarning() << __FUNCTION__ << "invalid rule index";
        return;
    }

    // Correct index
    index += 1;

    QVariantMap args {
        {"cmd", "removeRule"},
        {"index", QString::number(index)},
    };

    KAuth::Action modifyAction = buildModifyAction(args);
    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);

        if (!job->error())
        {
            QByteArray response = job->data().value("response", "").toByteArray();
            setProfile(Profile(response));
        } else {
            qWarning() << job->action().name() << job->errorString();
        }
        setBusy(false);
    });

    job->start();
}

void FirewalldClient::updateRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == NULL) {
        qWarning() << __FUNCTION__ << "NULL rule";
        return;
    }

    Rule rule = ruleWrapper->getRule();

    rule.setPosition(rule.getPosition() + 1);
    QVariantMap args {
        {"cmd", "editRule"},
        {"xml", rule.toXml()},
    };

    KAuth::Action modifyAction = buildModifyAction(args);
    KAuth::ExecuteJob *job = modifyAction.execute();
    connect(job, &KAuth::ExecuteJob::result, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);

        if (!job->error())
        {
            QByteArray response = job->data().value("response", "").toByteArray();
            setProfile(Profile(response));
        } else {
            qWarning() << job->action().name() << job->errorString();
        }
        setBusy(false);
    });

    job->start();
}

void FirewalldClient::moveRule(int from, int to)
{
    QList<Rule> rules = m_currentProfile.getRules();
    if (from < 0 || from >= rules.count()) {
        qWarning() << __FUNCTION__ << "invalid from index";
        return;
    }

    if (to < 0 || to >= rules.count()) {
        qWarning() << __FUNCTION__ << "invalid to index";
        return;
    }
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
    connect(job, &KAuth::ExecuteJob::finished, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);

        if (!job->error())
        {
            QByteArray response = job->data().value("response", "").toByteArray();
            setProfile(Profile(response));
        } else {
            qWarning() << job->action().name() << job->errorString();
        }
        setBusy(false);
    });

    job->start();
}

// QString FirewalldClient::defaultIncomingPolicy() const
// {
//     auto policy_t = m_currentProfile.getDefaultIncomingPolicy();
//     return Types::toString(policy_t);
// }
// 
// QString FirewalldClient::defaultOutgoingPolicy() const
// {
//     auto policy_t = m_currentProfile.getDefaultOutgoingPolicy();
//     return Types::toString(policy_t);
// }
// 
// LogListModel *FirewalldClient::logs()
// {
//     return m_logs;
// }


bool FirewalldClient::logsAutoRefresh() const
{
    return m_logsAutoRefresh;
}

RuleWrapper* FirewalldClient::createRuleFromConnection(const QString &protocol, const QString &localAddress, const QString &foreignAddres, const QString &status)
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
    const QString &inn,
    const QString &out)
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

IFirewallClientBackend* FirewalldClient::createMethod(FirewallClient* parent)
{
    IFirewallClientBackend *instance = new FirewalldClient(parent);
    return instance;
}

bool FirewalldClient::hasExecutable() const {
     return !QStandardPaths::findExecutable("ufw").isEmpty();
}
 
void FirewalldClient::setExecutable(const bool &hasExecutable){
    emit parentClient()->hasExecutableChanged(hasExecutable);
}

void FirewalldClient::refreshProfiles()
{

}

QDBusMessage FirewalldClient::dbusCall (QString method, QVariantList args) {
        QDBusMessage msg;
        // saving config call is in another interface which has the same name as SERVICE_NAME
        if(method == "runtimeToPermanent") {
            if(QDBusConnection::systemBus().isConnected()) {
            QDBusInterface iface(SERVICE_NAME, DBUS_PATH, SERVICE_NAME, QDBusConnection::systemBus());
            if(iface.isValid())
                msg= args.isEmpty() ? iface.call(QDBus::AutoDetect, method.toLatin1())
                    : iface.callWithArgumentList(QDBus::AutoDetect, method.toLatin1(), args);
            if(msg.type() == QDBusMessage::ErrorMessage)
                qDebug() << msg.errorMessage(); }
        } else {
        if(QDBusConnection::systemBus().isConnected()) {
            QDBusInterface iface(SERVICE_NAME, DBUS_PATH, INTERFACE_NAME, QDBusConnection::systemBus());
            if(iface.isValid())
                msg= args.isEmpty() ? iface.call(QDBus::AutoDetect, method.toLatin1())
                    : iface.callWithArgumentList(QDBus::AutoDetect, method.toLatin1(), args);
            if(msg.type() == QDBusMessage::ErrorMessage)
                qDebug() << msg.errorMessage(); }
     
        }
        return msg;
 }
