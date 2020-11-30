// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

/*
 * UFW KControl Module
 */

#ifndef IFIREWALLCLIENTBACKEND_H
#define IFIREWALLCLIENTBACKEND_H

#include "appprofiles.h"
#include "firewallclient.h"

#include <QString>
#include <QVector>

class KJob;
class LogListModel;
class Rule;
class RuleListModel;
class FirewallClient;

class Q_DECL_EXPORT IFirewallClientBackend : public QObject
{
    Q_OBJECT
public:
    IFirewallClientBackend(QObject *parent, const QVariantList &args);
    ~IFirewallClientBackend() = default;

    virtual QString name() const = 0;
    virtual void refresh() = 0;
    virtual RuleListModel *rules() const = 0;
    virtual bool isTcpAndUdp(int protocolIdx) = 0;
    virtual Rule *ruleAt(int index) = 0;

    Q_INVOKABLE virtual KJob *addRule(Rule *rule) = 0;
    Q_INVOKABLE virtual KJob *removeRule(int index) = 0;
    Q_INVOKABLE virtual KJob *updateRule(Rule *rule) = 0;
    Q_INVOKABLE virtual KJob *moveRule(int from, int to) = 0;

    Q_INVOKABLE virtual KJob *setEnabled(bool enabled) = 0;
    Q_INVOKABLE virtual KJob *queryStatus(FirewallClient::DefaultDataBehavior defaultsBehavior, FirewallClient::ProfilesBehavior profilesBehavior) = 0;
    Q_INVOKABLE virtual KJob *setDefaultIncomingPolicy(QString defaultIncomingPolicy) = 0;
    Q_INVOKABLE virtual KJob *setDefaultOutgoingPolicy(QString defaultOutgoingPolicy) = 0;
    Q_INVOKABLE virtual KJob *save();
    virtual void setLogsAutoRefresh(bool logsAutoRefresh) = 0;

    /* Creates a new Rule and returns it to the Qml side, passing arguments based on the Connection Table. */
    virtual Rule *createRuleFromConnection(
        const QString &protocol,
        const QString &localAddress,
        const QString &foreignAddres,
        const QString &status) = 0;

    virtual Rule *createRuleFromLog(
        const QString &protocol,
        const QString &sourceAddress,
        const QString &sourcePort,
        const QString &destinationAddress,
        const QString &destinationPort,
        const QString &inn) = 0;

    /* returns true if all of the dependencies of the firewall are installed on the system */
    virtual bool hasDependencies() const = 0;

    virtual bool enabled() const = 0;
    virtual QString defaultIncomingPolicy() const = 0;
    virtual QString defaultOutgoingPolicy() const = 0;
    virtual bool hasExecutable() const = 0;
    virtual LogListModel *logs() = 0;
    virtual bool logsAutoRefresh() const = 0;

    virtual void refreshProfiles() = 0;
    virtual FirewallClient::Capabilities capabilities() const;
    virtual QStringList knownProtocols() = 0;
    void setProfiles(const QVector<Entry> &profiles);
    QVector<Entry> profiles();
    Entry profileByName(const QString &profileName);

signals:
    void enabledChanged(bool enabled);
    void defaultIncomingPolicyChanged(const QString &defaultIncomingPolicy);
    void defaultOutgoingPolicyChanged(const QString &defaultOutgoingPolicy);
    void logsAutoRefreshChanged(bool logsAutoRefresh);
    // Is this even used?
    void hasExecutableChanged(bool changed);

    // TODO is this needed?
    void showErrorMessage(const QString &message);

private:
    QVector<Entry> m_profiles;
};

#endif
