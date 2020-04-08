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

#pragma once

#include <kcm_firewall_core_export.h>

#include <QObject>
#include <QTimer>
#include <functional>

class KJob;
class RuleListModel;
class RuleWrapper;
class LogListModel;
class IFirewallClientBackend;

/* This class is the entry point of the Firewall KCM
 * It uses internal FirewallImplementations defined in
 * the backend/ folder.
 *
 * To setup a firewall, this will look first for "higher abstractions"
 * like firewalld and ufw, then bsd specifics, etc.
 */

class KCM_FIREWALL_CORE_EXPORT FirewallClient : public QObject {
    Q_OBJECT
    /**
     * Whether the firewall is enabled
     */
    Q_PROPERTY(bool enabled READ enabled NOTIFY enabledChanged)
    Q_PROPERTY(QString defaultIncomingPolicy READ defaultIncomingPolicy NOTIFY defaultIncomingPolicyChanged)
    Q_PROPERTY(QString defaultOutgoingPolicy READ defaultOutgoingPolicy NOTIFY defaultOutgoingPolicyChanged)
    Q_PROPERTY(RuleListModel *rulesModel READ rulesModel CONSTANT)
    Q_PROPERTY(LogListModel *logsModel READ logsModel CONSTANT)
    Q_PROPERTY(bool logsAutoRefresh READ logsAutoRefresh WRITE setLogsAutoRefresh NOTIFY logsAutoRefreshChanged)
    Q_PROPERTY(QString backend READ backend WRITE setBackend NOTIFY backendChanged)
    Q_PROPERTY(bool hasExecutable READ hasExecutable NOTIFY hasExecutableChanged)

public:
    enum DefaultDataBehavior{DontReadDefaults, ReadDefaults};
    enum ProfilesBehavior{DontListenProfiles, ListenProfiles};

    explicit FirewallClient(QObject *parent = nullptr);

    Q_INVOKABLE static QStringList getKnownProtocols();
    Q_INVOKABLE static QStringList getKnownInterfaces();

    Q_INVOKABLE void refresh();
    RuleListModel* rulesModel() const;
    Q_INVOKABLE RuleWrapper* getRule(int index); // TODO move into the model?
    Q_INVOKABLE KJob *addRule(RuleWrapper * rule);
    Q_INVOKABLE KJob *removeRule(int index);
    Q_INVOKABLE KJob *updateRule(RuleWrapper * rule);
    Q_INVOKABLE KJob *moveRule(int from, int to);

    Q_INVOKABLE KJob *setEnabled(bool enabled);
    Q_INVOKABLE KJob *setDefaultIncomingPolicy(const QString &defaultIncomingPolicy);
    Q_INVOKABLE KJob *setDefaultOutgoingPolicy(const QString &defaultOutgoingPolicy);

    /* Creates a new Rule and returns it to the Qml side, passing arguments based on the Connecion Table. */
    Q_INVOKABLE RuleWrapper* createRuleFromConnection(
        const QString &protocol,
        const QString &localAddress,
        const QString &foreignAddres,
        const QString &status);

    Q_INVOKABLE RuleWrapper* createRuleFromLog(
        const QString &protocol,
        const QString &sourceAddress,
        const QString &sourcePort,
        const QString &destinationAddress,
        const QString &destinationPort,
        const QString &inn);

    bool enabled() const;
    bool hasExecutable() const;

    QString defaultIncomingPolicy() const;
    QString defaultOutgoingPolicy() const;
    QString backend() const;
    LogListModel* logsModel();
    bool logsAutoRefresh() const;
    using tcreateMethod = std::function<IFirewallClientBackend*(FirewallClient*)>;
    IFirewallClientBackend* create(const QString& name);
    static bool registerfw ( const QString name, tcreateMethod funcReg );

signals:
    void enabledChanged(const bool enabled);
    void defaultIncomingPolicyChanged(const QString &defaultIncomingPolicy);
    void defaultOutgoingPolicyChanged(const QString &defaultOutgoingPolicy);
    void logsAutoRefreshChanged(bool logsAutoRefresh);
    void backendChanged(const QString &backend);
    void hasExecutableChanged(bool changed);

    /**
     * Emitted when an error message should be displabed.
     *
     * This is typically shown as an inline message, e.g. "Failed to create action: Not authorized."
     */
    void showErrorMessage(const QString &message);

private:
    void setBackend(const QString &backend);
    void setLogsAutoRefresh(bool logsAutoRefresh);
    void queryStatus(DefaultDataBehavior defaultDataBehavior = ReadDefaults,
                     ProfilesBehavior ProfilesBehavior = ListenProfiles);

    IFirewallClientBackend *m_currentBackend;
    static std::map<QString, tcreateMethod> m_avaiableBackends;
};
