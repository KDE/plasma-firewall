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
#include <KLocalizedString>
#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QVariantList>

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
    queryStatus(FirewallClient::DefaultDataBehavior::ReadDefaults, 
                FirewallClient::ProfilesBehavior::ListenProfiles);
}

bool FirewalldClient::enabled() const
{
    /* QDBusMessage status; */
    /* status = HELPER::dbusCall("GetUnit", SYSTEMD::PATH, SYSTEMD::MANAGER_INTERFACE, */ 
    /*         SYSTEMD::INTERFACE, {"firewalld.service"}); */
    /* return status.type() == QDBusMessage::ErrorMessage ? false : true; */
    /* status = HELPER::dbusCall("GetUnit", SYSTEMD::PATH, SYSTEMD::MANAGER_INTERFACE, */ 
    return m_serviceStatus;    /* QDBusMessage status; */
}
void FirewalldClient::setEnabled(const bool value)
{
    if (m_serviceStatus != value) {
        m_serviceStatus = SYSTEMD::executeAction(static_cast<SYSTEMD::actions>(value));
        emit parentClient()->enabledChanged(value);
}
    qDebug() << "Service STATUS "<< m_serviceStatus;
    }

bool FirewalldClient::isBusy() const
{
    return m_isBusy;
}

void FirewalldClient::queryStatus(FirewallClient::DefaultDataBehavior defaultsBehavior, 
                                  FirewallClient::ProfilesBehavior profilesBehavior) {
    return;
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

void FirewalldClient::refreshLogs() {};
/* { */
/*     KAuth::Action action("org.kde.ufw.viewlog"); */
/*     action.setHelperId("org.kde.ufw"); */

/*     QVariantMap args; */
/*     if (m_rawLogs.size() > 0) */
/*         args["lastLine"] = m_rawLogs.last(); */

/*     action.setArguments(args); */

/*     KAuth::ExecuteJob *job = action.execute(); */
/*     connect(job, &KAuth::ExecuteJob::finished, [this](KJob * kjob) { */
/*             auto job = qobject_cast<KAuth::ExecuteJob *>(kjob); */

/*             if (!job->error()) { */
/*             QStringList newLogs = job->data().value("lines", "").toStringList(); */
/*             m_rawLogs.append(newLogs); */
/*             m_logs->addRawLogs(newLogs); */
/*             } else { */
/*             qWarning() << "org.kde.ufw.viewlog" << job->errorString(); */
/*             } */
/*             setBusy(false); */
/*             }); */

/*     job->start(); */
/* } */

void FirewalldClient::setStatus(const QString &status)
{
    m_status = status;
    emit parentClient()->statusChanged(m_status);
}

void FirewalldClient::setBusy(const bool &isBusy)
{
    if (m_isBusy != isBusy) {
        m_isBusy = isBusy;
        emit parentClient()->isBusyChanged(isBusy);
    }
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
    RuleWrapper *wrapper = new RuleWrapper(rule, this);

    return wrapper;
}

void FirewalldClient::addRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == NULL) {
        qWarning() << __FUNCTION__ << "NULL rule";
        return;
    }
    Rule rule = ruleWrapper->getRule();

    /* TODO create calls functions to ipv4 and ipv6 familty*/
    QVariantList dbusArgs = buildRule(rule);
    // check if it exist before adding.
    if (!HELPER::dbusCall("queryRule", HELPER::DBUS_PATH, HELPER::INTERFACE_NAME, HELPER::SERVICE_NAME, dbusArgs).arguments().at(0).toBool())
        HELPER::dbusCall("addRule", HELPER::DBUS_PATH, HELPER::INTERFACE_NAME, HELPER::SERVICE_NAME,dbusArgs);
}

void FirewalldClient::removeRule(int index)
{

    Rule rule = getRule(index)->getRule();
    /* TODO create calls functions to ipv4 and ipv6 familty*/
    QVariantList dbusArgs = buildRule(rule);
    HELPER::dbusCall("removeRule",  HELPER::DBUS_PATH, HELPER::INTERFACE_NAME, HELPER::SERVICE_NAME,dbusArgs);
}

void FirewalldClient::updateRule(RuleWrapper *ruleWrapper)
{
    if (ruleWrapper == NULL) {
        qWarning() << __FUNCTION__ << "NULL rule";
        return;
    }
    removeRule(ruleWrapper->position());
    addRule(ruleWrapper);
}

void FirewalldClient::moveRule(int from, int to)
{
    QVector<Rule> rules = m_currentProfile.getRules();
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

    /* KAuth::Action modifyAction = buildModifyAction(args); */
    /* KAuth::ExecuteJob *job = modifyAction.execute(); */
    /* connect(job, &KAuth::ExecuteJob::finished, [this](KJob * kjob) { */
    /*         auto job = qobject_cast<KAuth::ExecuteJob *>(kjob); */

    /*         if (!job->error()) { */
    /*         QByteArray response = job->data().value("response", "").toByteArray(); */
    /*         setProfile(Profile(response)); */
    /*         } else { */
    /*         qWarning() << job->action().name() << job->errorString(); */
    /*         } */
    /*         setBusy(false); */
    /*         }); */

    /* job->start(); */
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

IFirewallClientBackend *FirewalldClient::createMethod(FirewallClient *parent)
{
    IFirewallClientBackend *instance = new FirewalldClient(parent);
    return instance;
}

bool FirewalldClient::hasExecutable() const
{
    return !QStandardPaths::findExecutable("firewalld").isEmpty();
}

void FirewalldClient::setExecutable(const bool &hasExecutable)
{
    emit parentClient()->hasExecutableChanged(hasExecutable);
}

void FirewalldClient::refreshProfiles()
{

}

QDBusMessage HELPER::dbusCall(QString method, QString dpath, QString dinterface, QString dservice, QVariantList args= {}) {
    QDBusMessage msg;
    if(QDBusConnection::systemBus().isConnected()) {
        /* QDBusInterface iface(SERVICE_NAME, DBUS_PATH, INTERFACE_NAME, QDBusConnection::systemBus()); */
        QDBusInterface iface(dservice, dpath, dinterface, QDBusConnection::systemBus());
        if(iface.isValid())
            msg= args.isEmpty() ? iface.call(QDBus::AutoDetect, method.toLatin1())
                : iface.callWithArgumentList(QDBus::AutoDetect, method.toLatin1(), args);
        if(msg.type() == QDBusMessage::ErrorMessage)
            qDebug() << msg.errorMessage(); }
    return msg;
}

/* QDBusMessage FirewalldClient::dbusCall(QString method, QVariantList args) */
/* { */
/*     QDBusMessage msg; */
/*     // saving config call is in another interface which has the same name as SERVICE_NAME */
/*     if (method == "runtimeToPermanent") { */
/*         if (QDBusConnection::systemBus().isConnected()) { */
/*             QDBusInterface iface(SERVICE_NAME, DBUS_PATH, SERVICE_NAME, QDBusConnection::systemBus()); */
/*             if (iface.isValid()) */
/*                 msg = args.isEmpty() ? iface.call(QDBus::AutoDetect, method.toLatin1()) */
/*                     : iface.callWithArgumentList(QDBus::AutoDetect, method.toLatin1(), args); */
/*             if (msg.type() == QDBusMessage::ErrorMessage) */
/*                 qDebug() << msg.errorMessage(); */
/*         } */
/*     } else { */
/*         if (QDBusConnection::systemBus().isConnected()) { */
/*             QDBusInterface iface(SERVICE_NAME, DBUS_PATH, INTERFACE_NAME, QDBusConnection::systemBus()); */
/*             if (iface.isValid()) */
/*                 msg = args.isEmpty() ? iface.call(QDBus::AutoDetect, method.toLatin1()) */
/*                     : iface.callWithArgumentList(QDBus::AutoDetect, method.toLatin1(), args); */
/*             if (msg.type() == QDBusMessage::ErrorMessage) */
/*                 qDebug() << msg.errorMessage(); */
/*         } */
/*     } */
/*     return msg; */
/* } */

QVariantList FirewalldClient::buildRule(Rule r, FirewallClient::Ipv ipvfamily)
{
    QVariantMap args {
        {"priority", r.getPosition()},
            {"destinationPort", r.getDestPort()},
            {"sourcePort", r.getSourcePort()},
            {"type", r.getProtocol()},
            {"destinationAddress", r.getDestAddress()},
            {"sourceAddress", r.getSourceAddress()},
            {"table", "filter"}

    };

    r.getIncoming() ? args.insert("chain", "INPUT") : args.insert("chain", "OUTPUT");

    if (r.getAction() == Types::POLICY_ALLOW)
        args.insert("action", "ACCEPT");
    else if (r.getAction() == Types::POLICY_REJECT)
        args.insert("action", "REJECT");
    else
        args.insert("action", "DROP");

    QStringList firewalld_direct_rule = {"-p", args.value("type").toString(), "-j",
        args.value("action").toString()
    };

    if (!args.value("destinationAddress").toString().isEmpty())
        firewalld_direct_rule << "-d" <<  args.value("destinationAddress").toString();
    if (!args.value("destinationPort").toString().isEmpty())
        firewalld_direct_rule << "--dport=" +  args.value("destinationPort").toString();
    if (!args.value("sourceAddress").toString().isEmpty())
        firewalld_direct_rule << "-s" <<  args.value("sourceAddress").toString();
    if (!args.value("sourcePort").toString().isEmpty())
        firewalld_direct_rule << "--sport=" +  args.value("sourcePort").toString();

    if (ipvfamily == FirewallClient::IPV6)
        return QVariantList({"ipv6", args.value("table").toString(),
                args.value("chain").toString(), args.value("priority").toInt(), firewalld_direct_rule
                });
    qDebug() << firewalld_direct_rule;
    return QVariantList({"ipv4", args.value("table").toString(),
            args.value("chain").toString(), args.value("priority").toInt(), firewalld_direct_rule
            });
}
QString FirewalldClient::defaultIncomingPolicy() const {return "test";};
QString FirewalldClient::defaultOutgoingPolicy() const {return "test";};

void FirewalldClient::setDefaultIncomingPolicy(QString defaultIncomingPolicy) {};
void FirewalldClient::setDefaultOutgoingPolicy(QString defaultOutgoingPolicy) {};


LogListModel *FirewalldClient::logs()
{
    return m_logs;
}

SYSTEMD::actions SYSTEMD::executeAction(SYSTEMD::actions value) {
    QDBusMessage msg;
    if (QDBusConnection::systemBus().isConnected()) {
        if(value == SYSTEMD::START){
        QDBusInterface iface(SYSTEMD::INTERFACE, SYSTEMD::PATH, SYSTEMD::MANAGER_INTERFACE, 
                             QDBusConnection::systemBus());
            if (iface.isValid()) {
                msg = iface.callWithArgumentList(QDBus::AutoDetect, "StartUnit", 
                                             QVariantList({"firewalld.service", "fail"}));
                if (msg.type() == QDBusMessage::ErrorMessage){
                    qDebug() << msg.errorMessage();
                    return SYSTEMD::ERROR;
                }
            return SYSTEMD::START;
            }
        }
        else {
            QDBusInterface iface(SYSTEMD::INTERFACE, SYSTEMD::PATH, SYSTEMD::MANAGER_INTERFACE, 
                             QDBusConnection::systemBus());
            if (iface.isValid())
                msg = iface.callWithArgumentList(QDBus::AutoDetect, "StopUnit", 
                                                 QVariantList({"firewalld.service", "fail"}));
            if (msg.type() == QDBusMessage::ErrorMessage){
                qDebug() << msg.errorMessage();
                return SYSTEMD::ERROR;
            }
            return SYSTEMD::STOP;

        }
    }
    return SYSTEMD::ERROR;
}

