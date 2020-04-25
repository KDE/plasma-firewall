#include "firewalldjob.h"
#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusPendingCall>
#include <QtDBus/QDBusMetaType>
#include <QtDBus/QDBusPendingReply>
#include <QDebug>


namespace HELPER {
    const QString KCM_FIREWALLD_DIR = QStringLiteral("/etc/kcm/firewalld");
    const QString LOG_FILE = QStringLiteral("/var/log/firewalld.log");
    
    const QString BUS = QStringLiteral("org.fedoraproject.FirewallD1");
    const QString PATH = QStringLiteral("/org/fedoraproject/FirewallD1");
    const QString INTERFACE = QStringLiteral("org.fedoraproject.FirewallD1.direct");

}

namespace SAVE {
    const QString BUS = QStringLiteral("org.fedoraproject.FirewallD1");
    const QString PATH = QStringLiteral("/org/fedoraproject/FirewallD1");
    const QString INTERFACE = QStringLiteral("org.fedoraproject.FirewallD1");
    const QString METHOD = QStringLiteral("runtimeToPermanent");
    
}

namespace SYSTEMD {
    const QString BUS = QStringLiteral("org.freedesktop.systemd1");
    const QString PATH = QStringLiteral("/org/freedesktop/systemd1");
    const QString INTERFACE = QStringLiteral("org.freedesktop.systemd1.Manager");
}

enum {
  DBUSSYSTEMDERROR = KJob::UserDefinedError,
  DBUSFIREWALLDDERROR
};

const QDBusArgument &operator>>(const QDBusArgument &argument, firewalld_reply &mystruct)
{
    argument.beginStructure();
    argument >> mystruct.ipv >> mystruct.table >> mystruct.chain >> mystruct.priority >> mystruct.rules;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator<<(QDBusArgument &argument, const firewalld_reply &mystruct)
{
    argument.beginStructure();
    argument << mystruct.ipv << mystruct.table << mystruct.chain << mystruct.priority << mystruct.rules;
    argument.endStructure();
    return argument;
}

FirewalldJob::FirewalldJob() {};

FirewalldJob::FirewalldJob(const QByteArray& call, const QVariantList &args, const FirewalldJob::JobType &type) : m_type(type)
{
    setFirewalldMessage(call, args);
    qDBusRegisterMetaType<firewalld_reply>();
    qDBusRegisterMetaType<QList<firewalld_reply>>();
};

FirewalldJob::FirewalldJob(const SYSTEMD::actions &action, const JobType &type): m_type(type) {
    setStatus(action);
};

void FirewalldJob::setStatus(const SYSTEMD::actions action) {
    
    m_type == FirewalldJob::SYSTEMD ?  m_action = action : m_action = SYSTEMD::ERROR;
       
}

void FirewalldJob::setFirewalldMessage(const QByteArray &call, const QVariantList &args) {
    if (!m_type) {
        m_call = call;
        m_args = args;
    }
}

void FirewalldJob::systemdAction(const SYSTEMD::actions value) {
    
   
    QDBusMessage call;
    switch(value) {

        case SYSTEMD::START:
            call = QDBusMessage::createMethodCall(SYSTEMD::BUS,SYSTEMD::PATH,SYSTEMD::INTERFACE,"StartUnit");
            call.setArguments({"firewalld.service", "fail"});
            break;
        case SYSTEMD::STOP:
            call = QDBusMessage::createMethodCall(SYSTEMD::BUS,SYSTEMD::PATH,SYSTEMD::INTERFACE,"StopUnit");
            call.setArguments({"firewalld.service", "fail"});
            break;
        
        default:
            setErrorText("Invalid Call");
            setError(DBUSSYSTEMDERROR);
            emitResult();
    }
    QDBusPendingCall message = QDBusConnection::systemBus().asyncCall(call);
    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(message, this);
    
    /* waiting for start/stop of firewalld */
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *watcher) {
        QDBusPendingReply<> reply = *watcher; 
        watcher->deleteLater();
        if (reply.isError()) {
            setErrorText(reply.reply().errorMessage());
            setError(DBUSSYSTEMDERROR);
        }
        emitResult();
    });
}
void FirewalldJob::firewalldAction(const QByteArray &method, const QVariantList &args ) 
{    
    QDBusMessage call = QDBusMessage::createMethodCall(HELPER::BUS,HELPER::PATH,HELPER::INTERFACE,method);
    call.setArguments(args);
    QDBusPendingCall message = QDBusConnection::systemBus().asyncCall(call);
    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(message, this);
    if (args.isEmpty()){
        connect(watcher, &QDBusPendingCallWatcher::finished, [this](QDBusPendingCallWatcher *watcher) {
            QDBusPendingReply<QList<firewalld_reply>> reply = *watcher;
            watcher->deleteLater();
            if (reply.isError()) {
                setErrorText(reply.error().message());
                setError(DBUSFIREWALLDDERROR);
                qDebug() << errorString();
            }

            m_firewalldreply = reply.value();
            emitResult();
            
        });
    } else {
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *watcher) {
            QDBusPendingReply<> reply = *watcher;
            watcher->deleteLater();

            if (reply.isError()) {
                setErrorText(reply.reply().errorMessage());
                setError(DBUSFIREWALLDDERROR);
                qDebug() << errorString();
            }
            /* Firewalld does not save directly, need to call the another dbus interface
             * namespace SAVE define the bus,path,interface and method.
             * the method saveFirewalld do this call.
             */
            saveFirewalld(); 
            emitResult();
        });
    }
}


QList<firewalld_reply> FirewalldJob::get_firewalldreply()
{   
    return m_firewalldreply;
}

FirewalldJob::~FirewalldJob() {};

void FirewalldJob::start() {
    
    if (m_type == FirewalldJob::FIREWALLD){
        qDebug() << "firewalld " << m_call << m_args;
        firewalldAction(m_call, m_args);
    }
    else if (m_type == FirewalldJob::SYSTEMD) {
        qDebug() << "systemd" << m_type << m_action;
        systemdAction(m_action);
    }
    else
        // fake action (e.g : setting default inc/out policy)
        emitResult();
};

QString FirewalldJob::name() {
    
    return m_type == FirewalldJob::SYSTEMD ? 
            QString("systemd %1").arg(m_action) : 
            QString("firewalld %1").arg(QString(m_call));
        
}

void FirewalldJob::saveFirewalld() {
    QDBusPendingCall message = QDBusConnection::systemBus().asyncCall(QDBusMessage::createMethodCall(SAVE::BUS,SAVE::PATH,SAVE::INTERFACE,SAVE::METHOD));
    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(message, this);
    
    connect(watcher, &QDBusPendingCallWatcher::finished, [this](QDBusPendingCallWatcher *watcher) {
            QDBusPendingReply<> reply = *watcher;
            watcher->deleteLater();
            
            if (reply.isError()) {
                setErrorText(reply.error().message());
                setError(DBUSFIREWALLDDERROR);
                qDebug() << errorString();
                emitResult();
            }
        });
};
