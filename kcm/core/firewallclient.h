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


#ifndef FIREWALLCLIENT_H
#define FIREWALLCLIENT_H

#include <QObject>
#include <functional>

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

class FirewallClient : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool enabled READ enabled WRITE setEnabled NOTIFY enabledChanged)
    Q_PROPERTY(bool isBusy READ isBusy NOTIFY isBusyChanged)
    Q_PROPERTY(QString status READ status WRITE setStatus NOTIFY statusChanged)
    Q_PROPERTY(QString defaultIncomingPolicy READ defaultIncomingPolicy WRITE setDefaultIncomingPolicy NOTIFY defaultIncomingPolicyChanged)
    Q_PROPERTY(QString defaultOutgoingPolicy READ defaultOutgoingPolicy WRITE setDefaultOutgoingPolicy NOTIFY defaultOutgoingPolicyChanged)
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
    Q_INVOKABLE RuleListModel* rules() const;
    Q_INVOKABLE RuleWrapper* getRule(int index);
    Q_INVOKABLE void addRule(RuleWrapper * rule);
    Q_INVOKABLE void removeRule(int index);
    Q_INVOKABLE void updateRule(RuleWrapper * rule);
    Q_INVOKABLE void moveRule(int from, int to);

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
    bool isBusy() const;
    bool hasExecutable() const;

    QString status() const;
    QString defaultIncomingPolicy() const;
    QString defaultOutgoingPolicy() const;
    QString backend() const;
    Q_INVOKABLE LogListModel* logs();
    bool logsAutoRefresh() const;
    using tcreateMethod = std::function<IFirewallClientBackend*(FirewallClient*)>;
    IFirewallClientBackend* create(const QString& name);
    static bool registerfw ( const QString name, tcreateMethod funcReg );
    
signals:
    void isBusyChanged(const bool isBusy);
    void enabledChanged(const bool enabled);
    void statusChanged(const QString &status);
    void defaultIncomingPolicyChanged(const QString &defaultIncomingPolicy);
    void defaultOutgoingPolicyChanged(const QString &defaultOutgoingPolicy);
    void logsAutoRefreshChanged(bool logsAutoRefresh);
    void backendChanged(const QString &backend);
    void hasExecutableChanged(bool changed);
public slots:
    void setEnabled(bool enabled);
    void queryStatus(DefaultDataBehavior defaultDataBehavior = ReadDefaults,
                     ProfilesBehavior ProfilesBehavior = ListenProfiles);
    void setDefaultIncomingPolicy(const QString &defaultIncomingPolicy);
    void setDefaultOutgoingPolicy(const QString &defaultOutgoingPolicy);
    void setLogsAutoRefresh(bool logsAutoRefresh);
    void setBackend(const QString &backend);
    void setStatus(const QString& status);
private:
    IFirewallClientBackend *m_currentBackend;
    static std::map<QString, tcreateMethod> m_avaiableBackends;
    QString m_status;
};

#endif
