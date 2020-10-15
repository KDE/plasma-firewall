// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#ifndef NETSTATCLIENT_H
#define NETSTATCLIENT_H

#include <QObject>

#include "conectionsmodel.h"

#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(NetstatClientDebug)

class NetstatClient : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString status READ status WRITE setStatus NOTIFY statusChanged)
    Q_PROPERTY(ConnectionsModel *connectionsModel READ connectionsModel CONSTANT)

public:
    explicit NetstatClient(QObject *parent = nullptr);
    static NetstatClient *self();

    ConnectionsModel *connectionsModel() const;

    Q_SLOT void setStatus(const QString &message);
    QString status() const;
    Q_SIGNAL void statusChanged(const QString &output);

protected:
    QString mStatus;
    ConnectionsModel *m_connections;
};

#endif // NETSTATCLIENT_H
