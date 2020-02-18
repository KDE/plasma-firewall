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
    FirewallClient *parentClient() const;

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
    virtual bool isBusy() const = 0;
    virtual QString status() const = 0;
    virtual QString defaultIncomingPolicy() const = 0;
    virtual QString defaultOutgoingPolicy() const = 0;
    virtual bool hasExecutable() const = 0;
    virtual LogListModel* logs() = 0;
    virtual bool logsAutoRefresh() const = 0;


    virtual void refreshProfiles() = 0;

    void setProfiles(const QList<Entry> &profiles);
    QList<Entry> profiles();
    Entry profileByName(const QString &profileName);

public slots:
    virtual void setEnabled(bool enabled) = 0;
    virtual void queryStatus(bool readDefaults=true, bool listProfiles=true) = 0;
    virtual void setDefaultIncomingPolicy(QString defaultIncomingPolicy) = 0;
    virtual void setDefaultOutgoingPolicy(QString defaultOutgoingPolicy) = 0;
    virtual void setLogsAutoRefresh(bool logsAutoRefresh) = 0;
private:
    FirewallClient *m_parent;
    QList<Entry> m_profiles;
};

#endif
