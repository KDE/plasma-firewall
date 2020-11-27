// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#include "rule.h"
#include "appprofiles.h"
#include <KLocalizedString>
#include <QXmlStreamWriter>
#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QTextStream>
#include <arpa/inet.h>
#include <netdb.h>

#include "firewallclient.h"

// Keep in sync with kcm_ufw_helper.py
static const char *ANY_ADDR = "0.0.0.0/0";
static const char *ANY_ADDR_V6 = "::/0";
static const char *ANY_PORT = "any";

// Shorten an IPv6 address (if applicable)
static QString shortenAddress(const QString &addr)
{
    if (!addr.contains(":")) {
        return addr;
    }
    QByteArray bytes(addr.toLatin1());
    unsigned char num[16];

    if (inet_pton(AF_INET6, bytes.constData(), num) > 0) {
        char conv[41];
        if (NULL != inet_ntop(AF_INET6, num, conv, 41)) {
            return QLatin1String(conv);
        }
    }
    return addr;
}

static QString addIface(const QString &orig, const QString &iface)
{
    return iface.isEmpty() ? orig : i18nc("address on interface", "%1 on %2", orig, iface);
}

static QString serviceName(short port)
{
    static QMap<int, QString> serviceMap;

    if (serviceMap.contains(port)) {
        return serviceMap[port];
    }

    struct servent *ent = getservbyport(htons(port), 0L);

    if (ent && ent->s_name) {
        serviceMap[port] = ent->s_name;
        return serviceMap[port];
    }

    return {};
}

static QString formatPort(const QString &port, int prot)
{
    return port.isEmpty() ? Rule::protocolSuffix(prot, QString()) : port + Rule::protocolSuffix(prot);
}

static QString modifyAddress(const QString &addr, const QString &port)
{
    if (addr.isEmpty() || ANY_ADDR == addr || ANY_ADDR_V6 == addr) {
        return port.isEmpty() ? i18n("Anywhere") : QString();
    }

    return shortenAddress(addr);
}

static QString modifyPort(const QString &port, int prot, bool matchPortNoProto = false)
{
    if (port.isEmpty()) {
        return port;
    }
    // Does it match a pre-configured application?
    Types::PredefinedPort pp = Types::toPredefinedPort(port + Rule::protocolSuffix(prot));

    // When matching glog lines, the protocol is *always* specified - but don't always want this when
    // matching names...
    if (matchPortNoProto && Types::PP_COUNT == pp) {
        pp = Types::toPredefinedPort(port);
    }

    if (Types::PP_COUNT != pp) {
        return i18nc("service/application name (port numbers)", "%1 (%2)", Types::toString(pp, true), port + Rule::protocolSuffix(prot));
    }

    // Is it a service known to /etc/services ???
    bool ok(false);
    QString service;
    short portNum = port.toShort(&ok);

    if (ok) {
        service = serviceName(portNum);
    }

    if (!service.isEmpty()) {
        return i18nc("service/application name (port numbers)", "%1 (%2)", service, formatPort(port, prot));
    }

    // Just return port/servicename and protocol
    return formatPort(port, prot);
}

static QString modifyApp(const QString &app, const QString &port, int prot)
{
    if (app.isEmpty()) {
        return port;
    }

    // TODO: Send the profile, not the app name.
    Entry profile({});
    //     Entry profile(get(app));

    return i18nc("service/application name (port numbers)", "%1 (%2)", app, profile.name.isEmpty() ? formatPort(port, prot) : profile.ports);
}

int Rule::servicePort(const QString &name)
{
    static QMap<QString, int> serviceMap;

    if (serviceMap.contains(name)) {
        return serviceMap[name];
    }

    QByteArray l1 = name.toLatin1();
    struct servent *ent = getservbyname(l1.constData(), 0L);

    if (ent && ent->s_name) {
        serviceMap[name] = ntohs(ent->s_port);
        return serviceMap[name];
    }

    return 0;
}

QString Rule::protocolSuffix(int prot, const QString &sep)
{
    if (FirewallClient::isTcpAndUdp(prot)) {
        return {};
    }

    if (prot == -1) {
        qWarning() << "Invalid protocol -1, defaulting to" << FirewallClient::knownProtocols().at(0);
        prot = 0;
    }

    return sep + FirewallClient::knownProtocols().at(prot);
}

QString Rule::modify(const QString &address, const QString &port, const QString &application, const QString &iface, int protocol, bool matchPortNoProto)
{
    if ((port == ANY_PORT || port.isEmpty()) && (address.isEmpty() || ANY_ADDR == address || ANY_ADDR_V6 == address))
        return addIface(i18n("Anywhere"), iface);

    bool isAnyAddress = address.isEmpty() || ANY_ADDR == address || ANY_ADDR_V6 == address, isAnyPort = port.isEmpty() || ANY_PORT == port;
    QString bPort = application.isEmpty() ? modifyPort(port, protocol, matchPortNoProto) : modifyApp(application, port, protocol), bAddr = modifyAddress(address, port);

    return addIface(isAnyAddress ? isAnyPort ? i18n("Anywhere") : bPort : bAddr.isEmpty() ? bPort : bAddr + QChar(' ') + bPort, iface);
}

Rule::Rule()
    : m_position(0)
    , m_action(Types::POLICY_REJECT)
    , m_incoming(true)
    , m_ipv6(false)
    , m_protocol(0)
    , m_logtype(Types::LOGGING_OFF)
{
}

QString Rule::fromStr() const
{
    return modify(m_sourceAddress, m_sourcePort, m_sourceApplication, m_interfaceIn, m_protocol);
}

QString Rule::toStr() const
{
    return modify(m_destAddress, m_destPort, m_destApplication, m_interfaceOut, m_protocol);
}

QString Rule::actionStr() const
{
    return m_incoming ? i18nc("firewallAction incoming", "%1 incoming", Types::toString(m_action, true))
                     : i18nc("firewallAction outgoing", "%1 outgoing", Types::toString(m_action, true));
}

QString Rule::ipV6Str() const
{
    return m_ipv6 ? i18n("Yes") : QString();
}

QString Rule::loggingStr() const
{
    return Types::toString(m_logtype, true);
}

QString Rule::toXml() const
{
    QString xmlString;

    QXmlStreamWriter xml(&xmlString);

    xml.writeStartElement(QStringLiteral("rule"));

    if (m_position != 0) {
        xml.writeAttribute(QStringLiteral("position"), QString::number(m_position));
    }

    xml.writeAttribute(QStringLiteral("action"), Types::toString(m_action));
    xml.writeAttribute(QStringLiteral("direction"), m_incoming ? QStringLiteral("in") : QStringLiteral("out"));

    if (!m_destApplication.isEmpty()) {
        xml.writeAttribute(QStringLiteral("dapp"), m_destApplication);
    } else if (!m_destPort.isEmpty()) {
        xml.writeAttribute(QStringLiteral("dport"), m_destPort);
    }
    if (!m_sourceApplication.isEmpty()) {
        xml.writeAttribute(QStringLiteral("sapp"), m_sourceApplication);
    } else if (!m_sourcePort.isEmpty()) {
        xml.writeAttribute(QStringLiteral("sport"), m_sourcePort);
    }

    if (!FirewallClient::isTcpAndUdp(m_protocol)) {
        xml.writeAttribute(QStringLiteral("protocol"), FirewallClient::knownProtocols().at(m_protocol));
    }

    if (!m_destAddress.isEmpty()) {
        xml.writeAttribute(QStringLiteral("dst"), m_destAddress);
    }
    if (!m_sourceAddress.isEmpty()) {
        xml.writeAttribute(QStringLiteral("src"), m_sourceAddress);
    }

    if (!m_interfaceIn.isEmpty()) {
        xml.writeAttribute(QStringLiteral("interface_in"), m_interfaceIn);
    }
    if (!m_interfaceOut.isEmpty()) {
        xml.writeAttribute(QStringLiteral("interface_out"), m_interfaceOut);
    }

    xml.writeAttribute(QStringLiteral("logtype"), Types::toString(m_logtype));

    /*if (!description.isEmpty()) {
        xml.writeAttribute(QStringLiteral("descr"), description);
    }
    if (!hash.isEmpty()) {
        xml.writeAttribute(QStringLiteral("hash"), hash);
    }*/

    xml.writeAttribute(QStringLiteral("v6"), m_ipv6 ? QStringLiteral("True") : QStringLiteral("False"));

    xml.writeEndElement();

    return xmlString;
}
