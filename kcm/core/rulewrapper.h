// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#pragma once

#include <kcm_firewall_core_export.h>

#include <QObject>

#include "rule.h"
#include "types.h"

class KCM_FIREWALL_CORE_EXPORT RuleWrapper : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString policy READ policy WRITE setPolicy NOTIFY policyChanged)
    Q_PROPERTY(bool incoming READ incoming WRITE setIncoming NOTIFY incomingChanged)
    Q_PROPERTY(QString sourceAddress READ sourceAddress WRITE setSourceAddress NOTIFY sourceAddressChanged)
    Q_PROPERTY(QString sourcePort READ sourcePort WRITE setSourcePort NOTIFY sourcePortChanged)
    Q_PROPERTY(QString destinationAddress READ destinationAddress WRITE setDestinationAddress NOTIFY destinationAddressChanged)
    Q_PROPERTY(QString destinationPort READ destinationPort WRITE setDestinationPort NOTIFY destinationPortChanged)
    Q_PROPERTY(bool ipv6 READ ipv6 WRITE setIpv6 NOTIFY ipv6Changed)
    Q_PROPERTY(int protocol READ protocol WRITE setProtocol NOTIFY protocolChanged)
    Q_PROPERTY(int interface READ interface WRITE setInterface NOTIFY interfaceChanged)
    Q_PROPERTY(QString logging READ logging WRITE setLogging NOTIFY loggingChanged)
    Q_PROPERTY(int position READ position WRITE setPosition NOTIFY positionChanged)
public:
    explicit RuleWrapper(QObject *parent = nullptr);
    explicit RuleWrapper(Rule rule, QObject *parent = nullptr);

    QString policy() const;
    bool incoming() const;
    QString sourceAddress() const;
    QString sourcePort() const;
    QString destinationAddress() const;
    QString destinationPort() const;
    bool ipv6() const;
    int protocol() const;
    int interface() const;
    QString logging() const;

    Rule rule();
    int position() const;

signals:
    void policyChanged(const QString &policy);
    void directionChanged(const QString &direction);
    void sourceAddressChanged(const QString &sourceAddress);
    void sourcePortChanged(const QString &sourcePort);
    void destinationAddressChanged(const QString &destinationAddress);
    void destinationPortChanged(const QString &destinationPort);
    void ipv6Changed(bool ipv6);
    void protocolChanged(int protocol);
    void interfaceChanged(int interface);
    void loggingChanged(const QString &logging);
    void incomingChanged(bool incoming);

    void positionChanged(int position);

public slots:
    void setPolicy(const QString &policy);
    void setIncoming(bool incoming);
    void setSourceAddress(const QString &sourceAddress);
    void setSourcePort(const QString &sourcePort);
    void setDestinationAddress(const QString &destinationAddress);
    void setDestinationPort(const QString &destinationPort);
    void setIpv6(bool ipv6);
    void setProtocol(int protocol);
    void setInterface(int interface);
    void setLogging(const QString &logging);

    void setPosition(int position);

private:
    Rule m_rule;
    int m_interface;
};
