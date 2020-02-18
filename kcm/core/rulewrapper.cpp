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

#include "rulewrapper.h"
#include "types.h"
#include "firewallclient.h"

#include <QDebug>

RuleWrapper::RuleWrapper(QObject *parent) : QObject(parent), m_interface(0)
{
}

RuleWrapper::RuleWrapper(Rule rule, QObject *parent) : QObject(parent), m_rule(rule)
{
    int iface_index = FirewallClient::getKnownInterfaces().indexOf(m_rule.getInterfaceIn());
    m_interface = iface_index == -1 ? 0 : iface_index;
}

QString RuleWrapper::policy() const
{
    auto policy = m_rule.getAction();
    return Types::toString(policy);
}

bool RuleWrapper::incoming() const
{
    return m_rule.getIncoming();
}

QString RuleWrapper::sourceAddress() const
{
    return m_rule.getSourceAddress();
}

QString RuleWrapper::sourcePort() const
{
    return m_rule.getSourcePort();
}

QString RuleWrapper::destinationAddress() const
{
    return m_rule.getDestAddress();
}

QString RuleWrapper::destinationPort() const
{
    return m_rule.getDestPort();
}

int RuleWrapper::protocol() const
{
    auto protocol = m_rule.getProtocol();
    return protocol;
}

int RuleWrapper::interface() const
{
    return m_interface;
}

QString RuleWrapper::logging() const
{
    auto logging = m_rule.getLogging();
    return Types::toString(logging);
}

Rule RuleWrapper::getRule()
{
    return m_rule;
}

int RuleWrapper::position() const
{
    return m_rule.getPosition();
}

void RuleWrapper::setPolicy(const QString &policy)
{
    auto policy_t = Types::toPolicy(policy);

    if (policy_t == m_rule.getAction())
        return;

    m_rule.setAction(policy_t);
    emit policyChanged(policy);
}

void RuleWrapper::setIncoming(bool incoming)
{
    if (m_rule.getIncoming() == incoming)
        return;

    m_rule.setIncoming(incoming);
    emit incomingChanged(incoming);
}

void RuleWrapper::setSourceAddress(const QString &sourceAddress)
{
    if (m_rule.getSourceAddress().compare(sourceAddress) == 0)
        return;

    m_rule.setSourceAddress(sourceAddress);
    emit sourceAddressChanged(sourceAddress);
}

void RuleWrapper::setSourcePort(const QString &sourcePort)
{
    if (m_rule.getSourcePort().compare(sourcePort) == 0)
        return;

    m_rule.setSourcePort(sourcePort);
    emit sourcePortChanged(sourcePort);
}

void RuleWrapper::setDestinationAddress(const QString &destinationAddress)
{
    if (m_rule.getDestAddress().compare(destinationAddress)  == 0)
        return;

    m_rule.setDestAddress(destinationAddress);
    emit destinationAddressChanged(destinationAddress);
}

void RuleWrapper::setDestinationPort(const QString &destinationPort)
{
    if (m_rule.getDestPort().compare(destinationPort) == 0)
        return;

    m_rule.setDestPort(destinationPort);
    emit destinationPortChanged(destinationPort);
}

void RuleWrapper::setProtocol(int protocol)
{
    if (m_rule.getProtocol() == protocol)
        return;

    m_rule.setProtocol((Types::Protocol) protocol);
    emit protocolChanged(protocol);
}

void RuleWrapper::setInterface(int interface)
{
    if (m_interface == interface)
        return;

    m_rule.setInterfaceIn( interface != 0
        ? FirewallClient::getKnownInterfaces().at(interface)
        : QString());

    m_interface = interface;
    qDebug() << "new iface" << m_rule.getInterfaceIn();
    emit interfaceChanged(interface);
}

void RuleWrapper::setLogging(const QString &logging)
{
    auto logging_t = Types::toLogging(logging);
    if (m_rule.getLogging() == logging_t)
        return;

    m_rule.setLogging(logging_t);
    emit loggingChanged(logging);
}

void RuleWrapper::setPosition(int position)
{
    if (m_rule.getPosition() == position)
        return;

    m_rule.setPosition(position);
    emit positionChanged(position);
}


