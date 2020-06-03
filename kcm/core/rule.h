#ifndef UFW_RULE_H
#define UFW_RULE_H
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

#include <kcm_firewall_core_export.h>

#include <QObject>
#include <QString>

#include "types.h"

class KCM_FIREWALL_CORE_EXPORT Rule
{
public:
    static int servicePort(const QString &name);
    static QString protocolSuffix(Types::Protocol prot, const QString &sep = QString("/"));
    static QString modify(const QString &address, const QString &port, const QString &application, const QString &iface, const Types::Protocol &protocol, bool matchPortNoProto = false);

    Rule();
    Rule(Types::Policy pol,
         bool incomming,
         Types::Logging log,
         Types::Protocol prot,
         //          const QString &descr=QString(), const QString &hsh=QString(),
         const QString &srcHost = QString(),
         const QString &srcPort = QString(),
         const QString &destHost = QString(),
         const QString &destPort = QString(),
         const QString &ifaceIn = QString(),
         const QString &ifaceOut = QString(),
         const QString &srcApp = QString(),
         const QString &destApp = QString(),
         unsigned int i = 0,
         bool ipv6 = false)
        : m_position(i)
        , m_action(pol)
        , m_incoming(incomming)
        , m_ipv6(ipv6)
        , m_protocol(prot)
        , m_logtype(log)
        , m_destApplication(destApp)
        , m_sourceApplication(srcApp)
        , m_destAddress(destHost)
        , m_sourceAddress(srcHost)
        , m_destPort(destPort)
        , m_sourcePort(srcPort)
        , m_interfaceIn(ifaceIn)
        , m_interfaceOut(ifaceOut) // , description(descr), hash(hsh)
    {
    }

    QString toStr() const;
    QString fromStr() const;
    QString actionStr() const;
    QString protocolStr() const;
    QString ipV6Str() const;
    QString loggingStr() const;
    QString toXml() const;

    int position() const
    {
        return m_position;
    }
    Types::Policy action() const
    {
        return m_action;
    }
    bool incoming() const
    {
        return m_incoming;
    }
    bool ipv6() const
    {
        return m_ipv6;
    }
    const QString destApplication() const
    {
        return m_destApplication;
    }
    const QString sourceApplication() const
    {
        return m_sourceApplication;
    }
    const QString destAddress() const
    {
        return m_destAddress;
    }
    const QString sourceAddress() const
    {
        return m_sourceAddress;
    }
    const QString destPort() const
    {
        return m_destPort;
    }
    const QString sourcePort() const
    {
        return m_sourcePort;
    }
    const QString interfaceIn() const
    {
        return m_interfaceIn;
    }
    const QString interfaceOut() const
    {
        return m_interfaceOut;
    }
    Types::Protocol protocol() const
    {
        return m_protocol;
    }
    Types::Logging logging() const
    {
        return m_logtype;
    }
    void setPosition(unsigned int v)
    {
        m_position = v;
    }
    void setAction(Types::Policy v)
    {
        m_action = v;
    }
    void setIncoming(bool v)
    {
        m_incoming = v;
    }
    void setV6(bool v)
    {
        m_ipv6 = v;
    }
    void setDestApplication(const QString &v)
    {
        m_destApplication = v;
    }
    void setSourceApplication(const QString &v)
    {
        m_sourceApplication = v;
    }
    void setDestAddress(const QString &v)
    {
        m_destAddress = v;
    }
    void setSourceAddress(const QString &v)
    {
        m_sourceAddress = v;
    }
    void setDestPort(const QString &v)
    {
        m_destPort = v;
    }
    void setSourcePort(const QString &v)
    {
        m_sourcePort = v;
    }
    void setInterfaceIn(const QString &v)
    {
        m_interfaceIn = v;
    }
    void setInterfaceOut(const QString &v)
    {
        m_interfaceOut = v;
    }
    void setProtocol(Types::Protocol v)
    {
        m_protocol = v;
    }
    void setLogging(Types::Logging v)
    {
        m_logtype = v;
    }
    //     void setDescription(const QString &v)       { description=v; }
    //     void setHash(const QString &v)              { hash=v; }

    // 'different' is used in the EditRule dialog to know whether the rule has actually changed...
    bool different(const Rule &o) const
    {
        return m_logtype != o.m_logtype /*|| description!=o.description*/ || !(*this == o);
    }

    //     bool onlyDescrChanged(const Rule &o) const
    //     {
    //         return (*this==o) && logtype==o.logtype && description!=o.description;
    //     }

    bool operator==(const Rule &o) const
    {
            return m_action == o.m_action
                && m_incoming == o.m_incoming
                && m_ipv6 == o.m_ipv6
                && m_protocol == o.m_protocol
                && m_destApplication == o.m_destApplication
                && m_sourceApplication == o.m_sourceApplication
                && m_destAddress == o.m_destAddress
                && m_sourceAddress == o.m_sourceAddress
                && (m_destApplication.isEmpty() && o.m_destApplication.isEmpty() ? m_destPort == o.m_destPort : true)
                && (m_sourceApplication.isEmpty() && o.m_sourceApplication.isEmpty() ? m_sourcePort == o.m_sourcePort : true)
                && m_interfaceIn == o.m_interfaceIn
                && m_interfaceOut == o.m_interfaceOut;
    }

private:
    int m_position;
    Types::Policy m_action;
    bool m_incoming, m_ipv6;
    Types::Protocol m_protocol;
    Types::Logging m_logtype;
    QString m_destApplication;
    QString m_sourceApplication;
    QString m_destAddress;
    QString m_sourceAddress;
    QString m_destPort;
    QString m_sourcePort;
    QString m_interfaceIn;
    QString m_interfaceOut;
};

#endif
