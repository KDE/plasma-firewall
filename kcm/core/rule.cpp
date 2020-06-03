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


#include "rule.h"
#include "appprofiles.h"
#include <KLocalizedString>
#include <QtCore/QMap>
#include <QtCore/QByteArray>
#include <QtCore/QTextStream>
#include <QXmlStreamWriter>
#include <netdb.h>
#include <arpa/inet.h>

// Keep in sync with kcm_ufw_helper.py
static const char * ANY_ADDR     = "0.0.0.0/0";
static const char * ANY_ADDR_V6  = "::/0";
static const char * ANY_PORT     = "any";
static const char * ANY_PROTOCOL = "any";

// Shorten an IPv6 address (if applicable)
static QString shortenAddress(const QString &addr)
{
    if(addr.isEmpty() || !addr.contains(":")) {
        return addr;
    }
    QByteArray    bytes(addr.toLatin1());
    unsigned char num[16];

    if(inet_pton(AF_INET6, bytes.constData(), num)>0)
    {
        char conv[41];
        if(NULL!=inet_ntop(AF_INET6, num, conv, 41)) {
            return QLatin1String(conv);
        }
    }
    return addr;
}

static QString addIface(const QString &orig, const QString &iface)
{
    return iface.isEmpty() ? orig : i18nc("address on interface", "%1 on %2", orig, iface);
}

static QString getServiceName(short port)
{
    static QMap<int, QString> serviceMap;

    if(serviceMap.contains(port))
        return serviceMap[port];

    struct servent *ent=getservbyport(htons(port), 0L);

    if(ent && ent->s_name)
    {
        serviceMap[port]=ent->s_name;
        return serviceMap[port];
    }

    return QString();
}

static QString formatPort(const QString &port, Types::Protocol prot)
{
    return port.isEmpty() ? Rule::protocolSuffix(prot, QString())
                          : port+Rule::protocolSuffix(prot);
}

// Try to convert 'port' into a port number, not a service name...
static QString getPortNumber(const QString &port)
{
    if(port.indexOf(':') != -1) {
        return port;
    }
    bool ok;
    int  num = port.toInt(&ok);

    if(!ok) {
        num = Rule::getServicePort(port);
        if(num != 0) {
            return QString::number(num);
        }
    }

    return port;
}

static QString modifyAddress(const QString &addr, const QString &port)
{
    if(addr.isEmpty() || ANY_ADDR==addr || ANY_ADDR_V6==addr)
    {
        if(port.isEmpty())
            return i18n("Anywhere");
        else
            return QString();
    }

    return shortenAddress(addr);
}

static QString modifyPort(const QString &port, Types::Protocol prot, bool matchPortNoProto=false)
{
    if(port.isEmpty())
        return port;
    // Does it match a pre-configured application?
    Types::PredefinedPort pp=Types::toPredefinedPort(port+Rule::protocolSuffix(prot));

    // When matchin glog lines, the protocol is *always* specified - but dont alwys want this when
    // matching names...
    if(matchPortNoProto && Types::PP_COUNT==pp)
         pp=Types::toPredefinedPort(port);

    if(Types::PP_COUNT!=pp)
        return i18nc("serice/application name (port numbers)", "%1 (%2)", Types::toString(pp, true), port+Rule::protocolSuffix(prot));

    // Is it a service known to /etc/services ???
    bool    ok(false);
    QString service;
    short   portNum=port.toShort(&ok);

    if(ok)
        service=getServiceName(portNum);

    if(!service.isEmpty())
        return i18nc("serice/application name (port numbers)", "%1 (%2)", service, formatPort(port, prot));

    // Just return port/sericename and protocol
    return formatPort(port, prot);
}

static QString modifyApp(const QString &app, const QString &port, Types::Protocol prot)
{
    if(app.isEmpty())
        return port;

    // TODO: Send the profile, not the app name.
    Entry profile ({});
    //     Entry profile(get(app));

    return i18nc("serice/application name (port numbers)", "%1 (%2)", app, profile.name.isEmpty() ? formatPort(port, prot) : profile.ports);
}

int Rule::getServicePort(const QString &name)
{
    static QMap<QString, int> serviceMap;

    if(serviceMap.contains(name))
        return serviceMap[name];

    QByteArray l1=name.toLatin1();
    struct servent *ent=getservbyname(l1.constData(), 0L);

    if(ent && ent->s_name)
    {
        serviceMap[name]=ntohs(ent->s_port);
        return serviceMap[name];
    }

    return 0;
}

QString Rule::protocolSuffix(Types::Protocol prot, const QString &sep)
{
    return Types::PROTO_BOTH==prot ? "" : (sep+Types::toString(prot));
}

QString Rule::modify(const QString &address, const QString &port, const QString &application, const QString &iface,
                     const Types::Protocol &protocol, bool matchPortNoProto)
{
    if((port==ANY_PORT || port.isEmpty()) && (address.isEmpty() || ANY_ADDR==address || ANY_ADDR_V6==address))
        return addIface(i18n("Anywhere"), iface);

    bool    isAnyAddress=address.isEmpty() || ANY_ADDR==address || ANY_ADDR_V6==address,
            isAnyPort=port.isEmpty() || ANY_PORT==port;
    QString bPort=application.isEmpty() ? modifyPort(port, protocol, matchPortNoProto) : modifyApp(application, port, protocol),
            bAddr=modifyAddress(address, port);

    return addIface(isAnyAddress
                            ? isAnyPort
                                ? i18n("Anywhere")
                                : bPort
                            : bAddr.isEmpty()
                                ? bPort
                                : bAddr+QChar(' ')+bPort,
                      iface);
}

Rule::Rule()
    : position(0)
    , action(Types::POLICY_REJECT)
    , incoming(true)
    , v6(false)
    , protocol(Types::PROTO_BOTH)
    , logtype(Types::LOGGING_OFF)
{
}

QString Rule::fromStr() const
{
    return modify(sourceAddress, sourcePort, sourceApplication, interfaceIn, protocol);
}

QString Rule::toStr() const
{
    return modify(destAddress, destPort, destApplication, interfaceOut, protocol);
}

QString Rule::actionStr() const
{
    return incoming ? i18nc("firewallAction incomming", "%1 incoming", Types::toString(action, true))
                    : i18nc("firewallAction outgoing", "%1 outgoing", Types::toString(action, true));
}

QString Rule::ipV6Str() const
{
    return v6 ? i18n("Yes") : QString();
}

QString Rule::loggingStr() const
{
    return Types::toString(logtype, true);
}

QString Rule::toXml() const
{
    QString xmlString;

    QXmlStreamWriter xml(&xmlString);

    xml.writeStartElement(QStringLiteral("rule"));

    if (position != 0) {
        xml.writeAttribute(QStringLiteral("position"), QString::number(position));
    }

    xml.writeAttribute(QStringLiteral("action"), Types::toString(action));
    xml.writeAttribute(QStringLiteral("direction"), incoming ? QStringLiteral("in") : QStringLiteral("out"));

    if (!destApplication.isEmpty()) {
        xml.writeAttribute(QStringLiteral("dapp"), destApplication);
    } else if (!destPort.isEmpty()) {
        xml.writeAttribute(QStringLiteral("dport"), destPort);
    }
    if (!sourceApplication.isEmpty()) {
        xml.writeAttribute(QStringLiteral("sapp"), sourceApplication);
    } else if (!sourcePort.isEmpty()) {
        xml.writeAttribute(QStringLiteral("sport"), sourcePort);
    }

    if (protocol != Types::PROTO_BOTH) {
        xml.writeAttribute(QStringLiteral("protocol"), Types::toString(protocol));
    }

    if (!destAddress.isEmpty()) {
        xml.writeAttribute(QStringLiteral("dst"), destAddress);
    }
    if (!sourceAddress.isEmpty()) {
        xml.writeAttribute(QStringLiteral("src"), sourceAddress);
    }

    if (!interfaceIn.isEmpty()) {
        xml.writeAttribute(QStringLiteral("interface_in"), interfaceIn);
    }
    if (!interfaceOut.isEmpty()) {
        xml.writeAttribute(QStringLiteral("interface_out"), interfaceOut);
    }

    xml.writeAttribute(QStringLiteral("logtype"), Types::toString(logtype));

    /*if (!description.isEmpty()) {
        xml.writeAttribute(QStringLiteral("descr"), description);
    }
    if (!hash.isEmpty()) {
        xml.writeAttribute(QStringLiteral("hash"), hash);
    }*/

    xml.writeAttribute(QStringLiteral("v6"), v6 ? QStringLiteral("True") : QStringLiteral("False"));

    xml.writeEndElement();

    return xmlString;
}
