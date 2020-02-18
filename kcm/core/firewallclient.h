/*
 * Copyright 2020 Tomaz Canabrava <tcanabrava@kde.org>
 * Copyright 2017 Alexis López Zubieta <contact@azubieta.net>
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
    Q_PROPERTY(QString status READ status NOTIFY statusChanged)
    Q_PROPERTY(QString defaultIncomingPolicy READ defaultIncomingPolicy WRITE setDefaultIncomingPolicy NOTIFY defaultIncomingPolicyChanged)
    Q_PROPERTY(QString defaultOutgoingPolicy READ defaultOutgoingPolicy WRITE setDefaultOutgoingPolicy NOTIFY defaultOutgoingPolicyChanged)
    Q_PROPERTY(bool logsAutoRefresh READ logsAutoRefresh WRITE setLogsAutoRefresh NOTIFY logsAutoRefreshChanged)
    Q_PROPERTY(QString backend READ backend WRITE setBackend NOTIFY backendChanged)
    Q_PROPERTY(bool hasExecutable READ hasExecutable NOTIFY hasExecutableChanged)

public:
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
    void defaultIncomingPolicyChanged(QString defaultIncomingPolicy);
    void defaultOutgoingPolicyChanged(QString defaultOutgoingPolicy);
    void logsAutoRefreshChanged(bool logsAutoRefresh);
    void backendChanged(const QString &backend);
    void hasExecutableChanged(bool changed);
public slots:
    void setEnabled(bool enabled);
    void queryStatus(bool readDefaults=true, bool listProfiles=true);
    void setDefaultIncomingPolicy(QString defaultIncomingPolicy);
    void setDefaultOutgoingPolicy(QString defaultOutgoingPolicy);
    void setLogsAutoRefresh(bool logsAutoRefresh);
    void setBackend(const QString &backend);

private:
    IFirewallClientBackend *m_currentBackend;
    static std::map<QString, tcreateMethod> m_avaiableBackends;
};

#endif
