#ifndef FIREWALLDJOB_H
#define FIREWALLDJOB_H

#include <KJob>

class QDBusArgument;

struct firewalld_reply {
    QString ipv;
    QString table;
    QString chain;
    int priority = 0;
    QStringList rules;
};

Q_DECLARE_METATYPE(firewalld_reply);

namespace SYSTEMD {
    enum actions {STOP, START };
}

class FirewalldJob : public KJob {
    Q_OBJECT
    
public:
    enum JobType { FIREWALLD, SYSTEMD };
    FirewalldJob(const QByteArray &call, const QVariantList args = {}, JobType type=FIREWALLD);
    FirewalldJob(SYSTEMD::actions action, JobType type=SYSTEMD);
    FirewalldJob();
    ~FirewalldJob();
    void start() override;
    QList<firewalld_reply> get_firewalldreply();
    QString name();
    

private:
    void setFirewalldMessage(const QByteArray &call, QVariantList args = {});
    void saveFirewalld();
    void setStatus(const SYSTEMD::actions action);
    void systemdAction(SYSTEMD::actions value);
    void firewalldAction(const QByteArray &method, const QVariantList args = {} );
    QList<firewalld_reply> m_firewalldreply;
    JobType m_type;
    QByteArray m_call;
    QVariantList m_args;
    SYSTEMD::actions m_action;

};
#endif
