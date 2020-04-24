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

FirewalldJob::FirewalldJob(const QByteArray& call, const QVariantList args, FirewalldJob::JobType type) : m_type(type)
{
    setFirewalldMessage(call, args);
    qDBusRegisterMetaType<firewalld_reply>();
    qDBusRegisterMetaType<QList<firewalld_reply>>();
};

FirewalldJob::FirewalldJob(SYSTEMD::actions action, JobType type): m_type(type) {
    setStatus(action);
};

void FirewalldJob::setStatus(SYSTEMD::actions action) {
    if (m_type) {
        m_action = action;
    }
}

void FirewalldJob::setFirewalldMessage(const QByteArray &call, QVariantList args) {
    if (!m_type) {
        m_call = call;
        m_args = args;
    }
}

void FirewalldJob::systemdAction(SYSTEMD::actions value) {
    if (!QDBusConnection::systemBus().isConnected()) {
        setErrorText("NO systembus avaiable | " + QDBusConnection::systemBus().lastError().message());
        setError(DBUSSYSTEMDERROR);
        emitResult();
    }

    QDBusInterface iface(SYSTEMD::BUS, SYSTEMD::PATH, SYSTEMD::INTERFACE,
                QDBusConnection::systemBus());
    
    if(!iface.isValid()) {
        setErrorText("Interface is not valid | " + iface.lastError().message());
        setError(DBUSSYSTEMDERROR);
        emitResult();
    }
   
    QDBusPendingReply<> message;
    switch(value) {

        case SYSTEMD::START:
            message = iface.asyncCallWithArgumentList("StartUnit",
            {"firewalld.service", "fail"});
            break;
        case SYSTEMD::STOP:
            message = iface.asyncCallWithArgumentList("StopUnit",
            {"firewalld.service", "fail"});
            break;
        
        default:
            setErrorText("Something not expected happened");
            setError(DBUSSYSTEMDERROR);
            emitResult();
    }
    
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
void FirewalldJob::firewalldAction(const QByteArray &method, const QVariantList args ) 
{
    if (!QDBusConnection::systemBus().isConnected()) {
        setErrorText("NO systembus avaiable | " + QDBusConnection::systemBus().lastError().message());
        setError(DBUSFIREWALLDDERROR);
        emitResult();
    }
    
   QDBusInterface iface(HELPER::BUS, HELPER::PATH, HELPER::INTERFACE,
                QDBusConnection::systemBus());
   
    if(!iface.isValid()) {
        setErrorText("Interface is not valid | " + iface.lastError().message());
        setError(DBUSFIREWALLDDERROR);
        emitResult();
    }
    QDBusPendingCall message = args.isEmpty() ? iface.asyncCall(method) : iface.asyncCallWithArgumentList(method, args);
    QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(message, this);
    if (args.isEmpty()){
        connect(watcher, &QDBusPendingCallWatcher::finished, [this](QDBusPendingCallWatcher *watcher) {
            QDBusPendingReply<QList<firewalld_reply>> reply = *watcher;
            watcher->deleteLater();
            if (reply.isError()) {
                setErrorText(reply.error().message());
                setError(DBUSFIREWALLDDERROR);
                qDebug() << errorString();
                emitResult();
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
    else {
        qDebug() << "systemd" << m_type << m_action;
        systemdAction(m_action);
        
        
    }
};

QString FirewalldJob::name() {
    if(m_type)
        return QString("systemd %1").arg(m_action);
    else
        return QString("firewalld %1").arg(QString(m_call));
}

void FirewalldJob::saveFirewalld() {
    
    QDBusInterface iface(SAVE::BUS, SAVE::PATH, SAVE::INTERFACE,
                QDBusConnection::systemBus());
    
    if(!iface.isValid()) {
        setErrorText("Interface is not valid | " + iface.lastError().message());
        setError(DBUSFIREWALLDDERROR);
        emitResult();
    }
    QDBusPendingCall message = iface.asyncCall(SAVE::METHOD);
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
