// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2020 Lucas Biaggi <lbjanuario@gmail.com>
/*
 * Firewalld backend for plasma firewall
 */

#ifndef FIREWALLDCLIENT_H
#define FIREWALLDCLIENT_H

#include <QString>
#include <QTimer>
#include <QLoggingCategory>

#include <ifirewallclientbackend.h>
#include <profile.h>

class RuleListModel;
class LogListModel;
struct firewalld_reply;

Q_DECLARE_LOGGING_CATEGORY(FirewallDClientDebug)

class Q_DECL_EXPORT FirewalldClient : public IFirewallClientBackend
{
    Q_OBJECT
public:
    explicit FirewalldClient(QObject *parent, const QVariantList &args);

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
    KJob *setEnabled(const bool enabled) override;
    KJob *save() override;

    /* Creates a new Rule and returns it to the Qml side, passing arguments based
     * on the Connection Table. */
    RuleWrapper *createRuleFromConnection(const QString &protocol, const QString &localAddress, const QString &foreignAddres, const QString &status) override;

    RuleWrapper *createRuleFromLog(const QString &protocol, const QString &sourceAddress, const QString &sourcePort, const QString &destinationAddress, const QString &destinationPort, const QString &inn) override;

    bool enabled() const override;
    QString defaultIncomingPolicy() const override;
    QString defaultOutgoingPolicy() const override;
    QString name() const override;

    FirewallClient::Capabilities capabilities() const override;
    LogListModel *logs() override;
    bool logsAutoRefresh() const override;
    void setLogsAutoRefresh(bool logsAutoRefresh) override;
    static IFirewallClientBackend *createMethod(FirewallClient *parent);
    bool hasExecutable() const override;
    void refreshProfiles() override;
    bool hasDependencies() const override;
protected slots:
    void refreshLogs();

protected:
    void setExecutable(const bool &hasExecutable);
    QVector<Rule> extractRulesFromResponse(const QList<firewalld_reply> &reply) const;
    QVariantList buildRule(Rule r, FirewallClient::Ipv ipvfamily = FirewallClient::IPV4) const;
    void setProfile(Profile profile);

private:
    QString m_status;
    QStringList m_rawLogs;
    bool m_isBusy;
    Profile m_currentProfile;
    RuleListModel *m_rulesModel;
    LogListModel *m_logs;
    QTimer m_logsRefreshTimer;
    bool m_logsAutoRefresh;
    bool m_serviceStatus;
};

#endif // FIREWALLDCLIENT_H
