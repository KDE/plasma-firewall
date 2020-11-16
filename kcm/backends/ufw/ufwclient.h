// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#pragma once

#include <QString>
#include <QTimer>

#include <KAuth>

#include <ifirewallclientbackend.h>
#include <profile.h>

class RuleListModel;
class LogListModel;

class Q_DECL_EXPORT UfwClient : public IFirewallClientBackend
{
    Q_OBJECT
public:
    explicit UfwClient(QObject *parent, const QVariantList &args);

    void refresh() override;
    RuleListModel *rules() const override;
    RuleWrapper *ruleAt(int index) override;
    KJob *addRule(RuleWrapper *rule) override;
    KJob *removeRule(int index) override;
    KJob *updateRule(RuleWrapper *rule) override;
    KJob *moveRule(int from, int to) override;

    KJob *queryStatus(FirewallClient::DefaultDataBehavior defaultsBehavior, FirewallClient::ProfilesBehavior profilesBehavior) override;
    KJob *setDefaultIncomingPolicy(QString defaultIncomingPolicy) override;
    KJob *setDefaultOutgoingPolicy(QString defaultOutgoingPolicy) override;

    KJob *setEnabled(bool enabled) override;

    /* Creates a new Rule and returns it to the Qml side, passing arguments based on the Connection Table. */
    RuleWrapper *createRuleFromConnection(
        const QString &protocol,
        const QString &localAddress,
        const QString &foreignAddres,
        const QString &status) override;

    RuleWrapper *createRuleFromLog(
        const QString &protocol,
        const QString &sourceAddress,
        const QString &sourcePort,
        const QString &destinationAddress,
        const QString &destinationPort,
        const QString &inn) override;

    bool enabled() const override;
    QString defaultIncomingPolicy() const override;
    QString defaultOutgoingPolicy() const override;
    QString name() const override;

    LogListModel *logs() override;
    bool logsAutoRefresh() const override;
    void setLogsAutoRefresh(bool logsAutoRefresh) override;
    static IFirewallClientBackend *createMethod(FirewallClient *parent);
    bool hasExecutable() const override;
    void refreshProfiles() override;
    bool hasDependencies() const override;
protected slots:
    void refreshLogs();
    QStringList knownProtocols() override;

protected:
    void setProfile(Profile profile);
    void setExecutable(const bool &hasExecutable);
    KAuth::Action buildQueryAction(const QVariantMap &arguments);
    KAuth::Action buildModifyAction(const QVariantMap &arguments);

private:
    QStringList m_rawLogs;
    Profile m_currentProfile;
    RuleListModel *m_rulesModel;
    LogListModel *m_logs = nullptr;
    QTimer m_logsRefreshTimer;
    bool m_logsAutoRefresh;
    KAuth::Action m_queryAction;
    bool m_busy = false;
};
