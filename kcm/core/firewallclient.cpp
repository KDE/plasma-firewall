#include "firewallclient.h"

#include "rulelistmodel.h"
#include "loglistmodel.h"
#include "rulewrapper.h"

#include "ifirewallclientbackend.h"

#include <KLocalizedString>

#include <QStringList>
#include <QNetworkInterface>
#include <QList>
#include <QtGlobal>

// TODO: Figure out what's wrong with the registering.
#include "backends/ufw/ufwclient.h"

std::map<QString, FirewallClient::tcreateMethod> FirewallClient::m_avaiableBackends;

FirewallClient::FirewallClient(QObject *parent)
    : QObject(parent)
    , m_currentBackend(nullptr)
{
}

QStringList FirewallClient::getKnownProtocols()
{
    return { i18n("Any"), "TCP", "UDP" };
}

QStringList FirewallClient::getKnownInterfaces()
{
    QStringList interfaces_names({i18n("Any")});

    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    for (QNetworkInterface iface : qAsConst(interfaces))
        interfaces_names << iface.name();

    return interfaces_names;
}

void FirewallClient::refresh()
{
    Q_ASSERT(m_currentBackend);
    if(m_currentBackend)
        m_currentBackend->refresh();
}

RuleListModel* FirewallClient::rules() const
{
    if (m_currentBackend)
        return m_currentBackend->rules();
    return nullptr;
}

RuleWrapper* FirewallClient::getRule(int index)
{
    if (m_currentBackend)
        return m_currentBackend->getRule(index);
    return nullptr;
}

void FirewallClient::addRule(RuleWrapper * rule)
{
    Q_ASSERT(m_currentBackend);
    if(m_currentBackend)
        return m_currentBackend->addRule(rule);
}

void FirewallClient::removeRule(int index)
{
    Q_ASSERT(m_currentBackend);
    if(m_currentBackend)
        return m_currentBackend->removeRule(index);
}

void FirewallClient::updateRule(RuleWrapper * rule)
{
    Q_ASSERT(m_currentBackend);
    if(m_currentBackend)
        m_currentBackend->updateRule(rule);
}

void FirewallClient::moveRule(int from, int to)
{
    // TODO: Verify if this method is needed.
    Q_ASSERT(m_currentBackend);
    if(m_currentBackend)
        m_currentBackend->moveRule(from, to);
}


/* Creates a new Rule and returns it to the Qml side, passing arguments based on the Connecion Table. */
RuleWrapper* FirewallClient::createRuleFromConnection(
    const QString &protocol,
    const QString &localAddress,
    const QString &foreignAddres,
    const QString &status)
{
    Q_ASSERT(m_currentBackend);
    return m_currentBackend->createRuleFromConnection(protocol, localAddress, foreignAddres, status);
}

RuleWrapper* FirewallClient::createRuleFromLog(
    const QString &protocol,
    const QString &sourceAddress,
    const QString &sourcePort,
    const QString &destinationAddress,
    const QString &destinationPort,
    const QString &inn)
{
    Q_ASSERT(m_currentBackend);
    return m_currentBackend->createRuleFromLog(protocol, sourceAddress, sourcePort, destinationAddress, destinationPort, inn);
}

bool FirewallClient::enabled() const
{
    if (m_currentBackend)
        return m_currentBackend->enabled();
    return false;
}

bool FirewallClient::isBusy() const
{
    if (m_currentBackend)
        return m_currentBackend->isBusy();
    return true;
}

QString FirewallClient::status() const
{
    if (m_currentBackend)
        return m_currentBackend->status();
    return {};
}

QString FirewallClient::defaultIncomingPolicy() const
{
    if (m_currentBackend)
        return m_currentBackend->defaultIncomingPolicy();
    return {};
}

QString FirewallClient::defaultOutgoingPolicy() const
{
    if (m_currentBackend)
        return m_currentBackend->defaultOutgoingPolicy();
    return {};
}

LogListModel* FirewallClient::logs()
{
    // TODO: Perhaps this function is uneeded.
    if (m_currentBackend)
        return m_currentBackend->logs();
    return nullptr;
}

bool FirewallClient::logsAutoRefresh() const
{
    if (m_currentBackend)
        return m_currentBackend->logsAutoRefresh();
    return false;
}

void FirewallClient::setEnabled(bool enabled)
{
    if (m_currentBackend)
        m_currentBackend->setEnabled(enabled);
}

void FirewallClient::queryStatus(bool readDefaults, bool listProfiles)
{
    if (m_currentBackend)
        m_currentBackend->queryStatus(readDefaults, listProfiles);
}

void FirewallClient::setDefaultIncomingPolicy(QString defaultIncomingPolicy)
{
    if (m_currentBackend)
        m_currentBackend->setDefaultIncomingPolicy(defaultIncomingPolicy);
}

void FirewallClient::setDefaultOutgoingPolicy(QString defaultOutgoingPolicy)
{
    if (m_currentBackend)
        m_currentBackend->setDefaultOutgoingPolicy(defaultOutgoingPolicy);
}

void FirewallClient::setLogsAutoRefresh(bool logsAutoRefresh)
{
    if (m_currentBackend)
        m_currentBackend->setLogsAutoRefresh(logsAutoRefresh);
}

bool FirewallClient::hasExecutable() const
{
    if (m_currentBackend) {
        return m_currentBackend->hasExecutable();
    }
    return false;
}

void FirewallClient::setBackend(const QString& backend)
{
    if (m_currentBackend) {
        enabledChanged(false);
        delete m_currentBackend;
    }
    // For now let's use a lazy way of doing this.
    // To properly fix we should use a plugin system with dynamic libs.
    if (backend == "ufw") {
        m_currentBackend = new UfwClient(this);
    }
}

QString FirewallClient::backend() const
{
    if (m_currentBackend) {
        return m_currentBackend->name();
    }
    return {};
}

bool FirewallClient::registerfw ( const QString name, tcreateMethod funcReg )
{
    qDebug() << "Registering " << name;
    auto item = m_avaiableBackends.find(name);
    if(item == m_avaiableBackends.end())
    { 
        FirewallClient::m_avaiableBackends[name] = funcReg;
        return true;
    }
    return false;
}


IFirewallClientBackend* FirewallClient::create (const QString& name )
{
    auto item = m_avaiableBackends.find(name);
    if(item != m_avaiableBackends.end())
        return item->second(this);
    return nullptr;
}


