/*
 * FIREWALLD KControl Module
 *
 * Copyright 2011 Craig Drummond <craig.p.drummond@gmail.com>
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

#include "helper.h"
#include <QDebug>
#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QTextCodec>
#include <QDir>
#include <QDBusInterface>
#include <KAuth>
#include <KAuthHelperSupport>
#include <qvariant.h>
#include <QDBusArgument>
#include "firewalld_interface_config.h"
/* custom struct to receive reply from firewalld dbus interface */
struct firewalld_reply {
    QString ipv;
    QString table;
    QString chain;
    int priority = 0;
    QStringList rules = {};
};

Q_DECLARE_METATYPE(firewalld_reply)

const QDBusArgument &operator>>(const QDBusArgument &argument, firewalld_reply &mystruct)
{
    argument.beginStructure();
    argument >> mystruct.ipv >> mystruct.table >> mystruct.chain >> mystruct.priority >> mystruct.rules;
    argument.endStructure();
    return argument;
}

namespace {
    const QString KCM_FIREWALLD_DIR = QStringLiteral("/etc/kcm_firewalld");
    const QString LOG_FILE = QStringLiteral("/var/log/firewalld.log");
    const QString SERVICE_NAME = "org.fedoraproject.FirewallD1";
    const QString INTERFACE_NAME = SERVICE_NAME + ".direct";
    const QString DBUS_PATH = "/org/fedoraproject/FirewallD1";


    QDBusMessage dbusCall(QString method, QVariantList args= {}) {
        QDBusMessage msg;
        if(QDBusConnection::systemBus().isConnected()) {
            QDBusInterface iface(SERVICE_NAME, DBUS_PATH, INTERFACE_NAME, QDBusConnection::systemBus());
            if(iface.isValid())
                msg= args.isEmpty() ? iface.call(QDBus::AutoDetect, method.toLatin1())
                    : iface.callWithArgumentList(QDBus::AutoDetect, method.toLatin1(), args);
            if(msg.type() == QDBusMessage::ErrorMessage)
                qDebug() << msg.errorMessage(); }
        return msg;
    }
} // end namespace

namespace FIREWALLD {
    ActionReply Helper::query(const QVariantMap &args)
    {
        qDebug() << __FUNCTION__;
        ActionReply reply=args["defaults"].toBool();

        return reply;
    }

    ActionReply Helper::viewlog(const QVariantMap &args)
    {
        qDebug() << __FUNCTION__;

        QString     lastLine=args["lastLine"].toString(),
                    logFile=args["logFile"].toString();
        QFile       file(logFile.isEmpty() ? LOG_FILE : logFile);
        ActionReply reply;

        if(!file.open(QIODevice::ReadOnly|QIODevice::Text)) {
            return ActionReply::HelperErrorReply(STATUS_OPERATION_FAILED);
        }

        QStringList lines;
        while (!file.atEnd()) {
            QString line(file.readLine());

            if(line.contains(" [FIREWALLD ")) {
                if(!lastLine.isEmpty() && line==lastLine) {
                    lines.clear();
                    continue;
                }
                lines.append(line);
            }
        }

        reply.addData("lines", lines);
        return reply;
    }

    ActionReply Helper::modify(const QVariantMap &args)
    {
        qDebug() << __FUNCTION__;
        QString cmd=args["cmd"].toString();

        // QProcess converts its args using QString().toLocal8Bit()!!!, so use UTF-8 codec.
        QTextCodec::setCodecForLocale(QTextCodec::codecForName("UTF-8"));

        if("addRules"==cmd)
            return addRules(args, cmd);
        else if("removeRule"==cmd)
            return removeRule(args, cmd);
        else if("editRule"==cmd)
            return editRule(args, cmd);
        else if("permanent"==cmd)
            return permanent(cmd);

        ActionReply reply=ActionReply::HelperErrorReply(STATUS_INVALID_CMD);
        return reply;
    }

    ActionReply Helper::addRules(const QVariantMap &args, const QString &cmd)
    {
        unsigned int count=args["count"].toUInt();

        if(count>0)
        {
            QStringList cmdArgs;

            for(unsigned int i=0; i<count; ++i)
                cmdArgs << "--add="+args["xml"+QString::number(i)].toString();

            return run(cmdArgs, {"--list"}, cmd);
        }
        ActionReply reply=ActionReply::HelperErrorReply(STATUS_INVALID_ARGUMENTS);
        return reply;
    }


    ActionReply Helper::editRule(const QVariantMap &args, const QString &cmd)
    {
        return run({"--update="+args["xml"].toString()},
                {"--list"}, cmd);
    }


    ActionReply Helper::run(const QString &cmd, const QList<QVariant> &args)

    {
        qDebug() << __FUNCTION__ << args;

        QDBusMessage call = dbusCall(cmd, args);
        ActionReply reply;
        if(call.type() == QDBusMessage::ErrorMessage)
        {
            reply=ActionReply::HelperErrorReply(call.type());
        }
        else
        {
            reply.addData("cmd", cmd);
        }
        return reply;
    }

}

KAUTH_HELPER_MAIN("org.kde.firewalld", FIREWALLD::Helper)
