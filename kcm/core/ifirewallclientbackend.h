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

#ifndef IFIREWALLCLIENTBACKEND_H
#define IFIREWALLCLIENTBACKEND_H

#include "firewallclient.h"
#include "appprofiles.h"

#include <QString>

class LogListModel;
class RuleWrapper;
class RuleListModel;
class FirewallClient;

#define REGISTER_BACKEND(NAME, CreateMethod) \
namespace { \
static bool unused = FirewallClient::registerfw(NAME, CreateMethod); \
}

class IFirewallClientBackend : public QObject
{
    Q_OBJECT
public:
    IFirewallClientBackend(FirewallClient *parent);
    ~IFirewallClientBackend() = default;

    virtual QString name() const = 0;
    virtual void refresh() = 0;
    virtual RuleListModel* rules() const = 0;
    virtual RuleWrapper* getRule(int index) = 0;
    virtual void addRule(RuleWrapper * rule) = 0;
    virtual void removeRule(int index) = 0;
    virtual void updateRule(RuleWrapper * rule) = 0;
    virtual void moveRule(int from, int to) = 0;

    /* Creates a new Rule and returns it to the Qml side, passing arguments based on the Connecion Table. */
    virtual RuleWrapper* createRuleFromConnection(
        const QString &protocol,
        const QString &localAddress,
        const QString &foreignAddres,
        const QString &status) = 0;

    virtual RuleWrapper* createRuleFromLog(
        const QString &protocol,
        const QString &sourceAddress,
        const QString &sourcePort,
        const QString &destinationAddress,
        const QString &destinationPort,
        const QString &inn) = 0;

    virtual bool enabled() const = 0;
    virtual bool busy() const;
    virtual FirewallClient::Status status() const = 0;
    virtual QString defaultIncomingPolicy() const = 0;
    virtual QString defaultOutgoingPolicy() const = 0;
    virtual bool hasExecutable() const = 0;
    virtual LogListModel* logs() = 0;
    virtual bool logsAutoRefresh() const = 0;

    virtual void refreshProfiles() = 0;

    void setProfiles(const QVector<Entry> &profiles);
    QVector<Entry> profiles();
    Entry profileByName(const QString &profileName);

signals:
    void enabledChanged(bool enabled);
    void busyChanged(bool busy);
    void statusChanged(FirewallClient::Status status);
    void defaultIncomingPolicyChanged(const QString &defaultIncomingPolicy);
    void defaultOutgoingPolicyChanged(const QString &defaultOutgoingPolicy);
    void logsAutoRefreshChanged(bool logsAutoRefresh);
    // Is this even used?
    void hasExecutableChanged(bool changed);

    void showSuccessMessage(const QString &message);
    void showErrorMessage(const QString &message);

public slots:
    virtual void setEnabled(bool enabled) = 0;
    virtual void queryStatus(FirewallClient::DefaultDataBehavior defaultsBehavior, FirewallClient::ProfilesBehavior profilesBehavior) = 0;
    virtual void setDefaultIncomingPolicy(QString defaultIncomingPolicy) = 0;
    virtual void setDefaultOutgoingPolicy(QString defaultOutgoingPolicy) = 0;
    virtual void setLogsAutoRefresh(bool logsAutoRefresh) = 0;

private:
    QVector<Entry> m_profiles;
};

#endif
