/*
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
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

#ifndef FIREWALLDCLIENT_H
#define FIREWALLDCLIENT_H

#include <QObject>
#include <QString>
#include <QTimer>

#include <QtDBus/QDBusMessage>

//#include <KAuth>

#include "core/profile.h"
#include "core/rulelistmodel.h"
#include "core/loglistmodel.h"
#include "core/ifirewallclientbackend.h"
#include "core/appprofiles.h"
#include "core/rule.h"
#include <functional>

struct firewalld_reply {
    QString ipv;
    QString table;
    QString chain;
    int priority = 0;
    QStringList rules = {};
};

Q_DECLARE_METATYPE(firewalld_reply)

    namespace {
        //const QString KCM_FIREWALLD_DIR = QStringLiteral("/etc/kcm_firewalld");
        const QString LOG_FILE = QStringLiteral("/var/log/firewalld.log");
        const QString SERVICE_NAME = "org.fedoraproject.FirewallD1";
        const QString INTERFACE_NAME = SERVICE_NAME + ".direct";
        const QString DBUS_PATH = "/org/fedoraproject/FirewallD1";

    }

class FirewalldClient : public IFirewallClientBackend
{
    Q_OBJECT
    public:
        explicit FirewalldClient(FirewallClient *parent);

        void refresh() override;
        RuleListModel* rules() const override;
        RuleWrapper* getRule(int index) override;
        void addRule(RuleWrapper *rule) override;
        void removeRule(RuleWrapper *rule) override;
        void updateRule(RuleWrapper * rule) override;
        void moveRule(int from, int to) override;
        /* Creates a new Rule and returns it to the Qml side, passing arguments based on the Connecion Table. */
        RuleWrapper* createRuleFromConnection(
                const QString &protocol,
                const QString &localAddress,
                const QString &foreignAddres,
                const QString &status) override;

        RuleWrapper* createRuleFromLog(
                const QString &protocol,
                const QString &sourceAddress,
                const QString &sourcePort,
                const QString &destinationAddress,
                const QString &destinationPort,
                const QString &inn,
                const QString &out) override;

        bool enabled() const override;
        bool isBusy() const override;
        QString status() const override;
        //QString defaultIncomingPolicy() const override;
        //QString defaultOutgoingPolicy() const override;
        QString name() const override;

        LogListModel* logs() override;
        bool logsAutoRefresh() const override;
        static IFirewallClientBackend* createMethod(FirewallClient *parent);
        bool hasExecutable() const override;
        void refreshProfiles() override;

        public slots:
            void queryStatus(bool readDefaults=true, bool listProfiles=true) override;
        //void setDefaultIncomingPolicy(QString defaultIncomingPolicy) override;
        //void setDefaultOutgoingPolicy(QString defaultOutgoingPolicy) override;

        void setLogsAutoRefresh(bool logsAutoRefresh) override;
        void setEnabled(bool enabled) override;

        protected slots:
            void refreshLogs();

    protected:
        void setStatus(const QString &status);
        void setBusy(const bool &busy);
        void setExecutable(const bool &hasExecutable);
        KAuth::Action buildQueryAction(const QVariantMap &arguments);
        KAuth::Action buildModifyAction(const QVariantMap &arguments);
        QVariantList buildRule(Rule r, bool isIpv6);
        QDBusMessage dbusCall(QString method, QVariantList args= {});
    private:
        QString m_status;
        QStringList         m_rawLogs;
        bool                m_isBusy;
        Profile        m_currentProfile;
        RuleListModel*      m_rulesModel;
        LogListModel*       m_logs;
        QTimer              m_logsRefreshTimer;
        //    Blocker       *blocker;
        bool m_logsAutoRefresh;
        //KAuth::Action m_queryAction;

};

#endif // FIREWALLDCLIENT_H

