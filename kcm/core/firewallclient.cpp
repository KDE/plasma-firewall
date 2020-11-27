// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#include "firewallclient.h"

#include "loglistmodel.h"
#include "rulelistmodel.h"

#include "ifirewallclientbackend.h"

#include <KLocalizedString>
#include <KPluginFactory>
#include <KPluginLoader>
#include <KPluginMetaData>

#include <QList>
#include <QNetworkInterface>
#include <QStringList>
#include <QtGlobal>

Q_LOGGING_CATEGORY(FirewallClientDebug, "firewall.client")

IFirewallClientBackend *FirewallClient::m_currentBackend = nullptr;

FirewallClient::FirewallClient(QObject *parent)
    : QObject(parent)
{
    if (!m_currentBackend) {
        setBackend("ufw");
    }
    if (!m_currentBackend) {
        setBackend("firewalld");
    }
}

QStringList FirewallClient::knownProtocols()
{
    return m_currentBackend->knownProtocols();
}

bool FirewallClient::isTcpAndUdp(int protocolIdx)
{
    return m_currentBackend->isTcpAndUdp(protocolIdx);
}

QStringList FirewallClient::knownInterfaces()
{
    QStringList interface_names({i18n("Any")});

    for (const QNetworkInterface &iface : QNetworkInterface::allInterfaces()) {
        interface_names << iface.name();
    }

    return interface_names;
}

void FirewallClient::refresh()
{
    if (!m_currentBackend) {
        return;
    }
    m_currentBackend->refresh();
}

RuleListModel *FirewallClient::rulesModel() const
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->rules();
}

Rule *FirewallClient::ruleAt(int index)
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->ruleAt(index);
}

KJob *FirewallClient::addRule(Rule *rule)
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->addRule(rule);
}

KJob *FirewallClient::removeRule(int index)
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->removeRule(index);
}

KJob *FirewallClient::updateRule(Rule *rule)
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->updateRule(rule);
}

KJob *FirewallClient::moveRule(int from, int to)
{
    // TODO: Verify if this method is needed.
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->moveRule(from, to);
}

KJob *FirewallClient::save()
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->save();
}

QString FirewallClient::name() const
{
    if (!m_currentBackend) {
        return {};
    }
    return m_currentBackend->name();
}
FirewallClient::Capabilities FirewallClient::capabilities() const
{
    if (!m_currentBackend) {
        return FirewallClient::Capability::None;
    }
    return m_currentBackend->capabilities();
}

/* Creates a new Rule and returns it to the Qml side, passing arguments based
 * on the Connection Table. */
Rule *FirewallClient::createRuleFromConnection(const QString& protocol,
    const QString& localAddress, const QString& foreignAddres,
    const QString& status)
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->createRuleFromConnection(
        protocol, localAddress, foreignAddres, status);
}

Rule *FirewallClient::createRuleFromLog(const QString& protocol,
    const QString& sourceAddress, const QString& sourcePort,
    const QString& destinationAddress, const QString& destinationPort,
    const QString& inn)
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->createRuleFromLog(protocol, sourceAddress,
        sourcePort, destinationAddress, destinationPort, inn);
}

bool FirewallClient::enabled() const
{
    if (!m_currentBackend) {
        return false;
    }
    return m_currentBackend->enabled();
}

QString FirewallClient::defaultIncomingPolicy() const
{
    if (!m_currentBackend) {
        return {};
    }
    return m_currentBackend->defaultIncomingPolicy();
}

QString FirewallClient::defaultOutgoingPolicy() const
{
    if (!m_currentBackend) {
        return {};
    }
    return m_currentBackend->defaultOutgoingPolicy();
}

LogListModel *FirewallClient::logsModel() const
{
    // TODO: Perhaps this function is uneeded.
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->logs();
}

bool FirewallClient::logsAutoRefresh() const
{
    if (!m_currentBackend) {
        return false;
    }
    return m_currentBackend->logsAutoRefresh();
}

KJob *FirewallClient::setEnabled(bool enabled)
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->setEnabled(enabled);
}

void FirewallClient::queryStatus(
    DefaultDataBehavior defaultsBehavior, ProfilesBehavior profilesBehavior)
{
    if (!m_currentBackend) {
        return;
    }
    m_currentBackend->queryStatus(defaultsBehavior, profilesBehavior);
}

KJob *FirewallClient::setDefaultIncomingPolicy(const QString &defaultIncomingPolicy)
{
    if (!m_currentBackend) {
        return nullptr;
    }
    return m_currentBackend->setDefaultIncomingPolicy(defaultIncomingPolicy);
}

KJob *FirewallClient::setDefaultOutgoingPolicy(const QString &defaultOutgoingPolicy)
{
    if (!m_currentBackend) {
        return nullptr;
    }

    return m_currentBackend->setDefaultOutgoingPolicy(defaultOutgoingPolicy);
}

void FirewallClient::setLogsAutoRefresh(bool logsAutoRefresh)
{
    if (!m_currentBackend) {
        return;
    }
    m_currentBackend->setLogsAutoRefresh(logsAutoRefresh);
}

bool FirewallClient::hasExecutable() const
{
    if (!m_currentBackend) {
        return false;
    }
    return m_currentBackend->hasExecutable();
}

void FirewallClient::setBackend(const QString &backend)
{
    if (m_currentBackend) {
        enabledChanged(false);
        delete m_currentBackend;
        m_currentBackend = nullptr;
    }

    const auto plugins = KPluginLoader::findPlugins(QStringLiteral("kf5/plasma_firewall"));

    for (const KPluginMetaData &metadata : plugins) {
        if (metadata.pluginId() != backend + QLatin1String("backend")) {
            continue;
        }

        KPluginFactory *factory = KPluginLoader(metadata.fileName()).factory();
        if (!factory) {
            continue;
        }

        auto perhaps = factory->create<IFirewallClientBackend>(this, QVariantList() /*args*/);
        if (perhaps->hasDependencies()) {
            qCDebug(FirewallClientDebug) << "Backend " << backend << "Loaded";
            m_currentBackend = perhaps;
            break;
        } else {
            qCDebug(FirewallClientDebug) << "Backend " << backend << "Failed to meet dependencies";
            perhaps->deleteLater();
        }
    }

    if (!m_currentBackend) {
        qCDebug(FirewallClientDebug) << "Could not find backend" << backend;
        return;
    }

    connect(m_currentBackend, &IFirewallClientBackend::enabledChanged,
        this, &FirewallClient::enabledChanged);
    connect(m_currentBackend,
        &IFirewallClientBackend::defaultIncomingPolicyChanged, this,
        &FirewallClient::defaultIncomingPolicyChanged);
    connect(m_currentBackend,
        &IFirewallClientBackend::defaultOutgoingPolicyChanged, this,
        &FirewallClient::defaultOutgoingPolicyChanged);
    connect(m_currentBackend,
        &IFirewallClientBackend::logsAutoRefreshChanged, this,
        &FirewallClient::logsAutoRefreshChanged);
    connect(m_currentBackend,
        &IFirewallClientBackend::hasExecutableChanged, this,
        &FirewallClient::hasExecutableChanged);
    connect(m_currentBackend, &IFirewallClientBackend::showErrorMessage,
        this, &FirewallClient::showErrorMessage);
}

QString FirewallClient::backend() const
{
    if (!m_currentBackend) {
        return {};
    }
    return m_currentBackend->name();
}
