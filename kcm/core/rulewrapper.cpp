// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#include "rulewrapper.h"
#include "firewallclient.h"
#include "types.h"


RuleWrapper::RuleWrapper(QObject *parent)
    : QObject(parent)
    , m_interface(0)
{
}

RuleWrapper::RuleWrapper(Rule rule, QObject *parent)
    : QObject(parent)
    , m_rule(rule)
{
    int iface_index = FirewallClient::knownInterfaces().indexOf(m_rule.interfaceIn());
    m_interface = iface_index == -1 ? 0 : iface_index;
}

QString RuleWrapper::policy() const
{
    auto policy = m_rule.action();
    return Types::toString(policy);
}

bool RuleWrapper::incoming() const
{
    return m_rule.incoming();
}

QString RuleWrapper::sourceAddress() const
{
    return m_rule.sourceAddress();
}

QString RuleWrapper::sourcePort() const
{
    return m_rule.sourcePort();
}

QString RuleWrapper::destinationAddress() const
{
    return m_rule.destAddress();
}

QString RuleWrapper::destinationPort() const
{
    return m_rule.destPort();
}

bool RuleWrapper::ipv6() const
{
    return m_rule.ipv6();
}

int RuleWrapper::protocol() const
{
    auto protocol = m_rule.protocol();
    return protocol;
}

int RuleWrapper::interface() const
{
    return m_interface;
}

QString RuleWrapper::logging() const
{
    auto logging = m_rule.logging();
    return Types::toString(logging);
}

Rule RuleWrapper::rule()
{
    return m_rule;
}

int RuleWrapper::position() const
{
    return m_rule.position();
}

void RuleWrapper::setPolicy(const QString &policy)
{
    auto policy_t = Types::toPolicy(policy);

    if (policy_t == m_rule.action()) {
        return;
    }

    m_rule.setAction(policy_t);
    emit policyChanged(policy);
}

void RuleWrapper::setIncoming(bool incoming)
{
    if (m_rule.incoming() == incoming) {
        return;
    }

    m_rule.setIncoming(incoming);
    emit incomingChanged(incoming);
}

void RuleWrapper::setSourceAddress(const QString &sourceAddress)
{
    if (m_rule.sourceAddress() == sourceAddress) {
        return;
    }

    m_rule.setSourceAddress(sourceAddress);
    emit sourceAddressChanged(sourceAddress);
}

void RuleWrapper::setSourcePort(const QString &sourcePort)
{
    if (m_rule.sourcePort() == sourcePort) {
        return;
    }

    m_rule.setSourcePort(sourcePort);
    emit sourcePortChanged(sourcePort);
}

void RuleWrapper::setDestinationAddress(const QString &destinationAddress)
{
    if (m_rule.destAddress() == destinationAddress) {
        return;
    }

    m_rule.setDestAddress(destinationAddress);
    emit destinationAddressChanged(destinationAddress);
}

void RuleWrapper::setDestinationPort(const QString &destinationPort)
{
    if (m_rule.destPort() == destinationPort) {
        return;
    }

    m_rule.setDestPort(destinationPort);
    emit destinationPortChanged(destinationPort);
}

void RuleWrapper::setIpv6(bool ipv6)
{
    if (m_rule.ipv6() == ipv6) {
        return;
    }

    m_rule.setV6(ipv6);
    emit ipv6Changed(ipv6);
}

void RuleWrapper::setProtocol(int protocol)
{
    if (m_rule.protocol() == protocol) {
        return;
    }

    m_rule.setProtocol((Types::Protocol)protocol);
    emit protocolChanged(protocol);
}

void RuleWrapper::setInterface(int interface)
{
    if (m_interface == interface) {
        return;
    }

    m_rule.setInterfaceIn(interface != 0 ? FirewallClient::knownInterfaces().at(interface) : QString());

    m_interface = interface;
    emit interfaceChanged(interface);
}

void RuleWrapper::setLogging(const QString &logging)
{
    auto logging_t = Types::toLogging(logging);
    if (m_rule.logging() == logging_t) {
        return;
    }

    m_rule.setLogging(logging_t);
    emit loggingChanged(logging);
}

void RuleWrapper::setPosition(int position)
{
    if (m_rule.position() == position) {
        return;
    }

    m_rule.setPosition(position);
    emit positionChanged(position);
}
