// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#ifndef CONECTIONSMODEL_H
#define CONECTIONSMODEL_H

#include <QAbstractListModel>
#include <QTimer>

#include <QLoggingCategory>

#include "netstathelper.h"

Q_DECLARE_LOGGING_CATEGORY(ConnectionsModelDebug)

struct ConnectionsData {
    QString protocol;
    QString localAddress;
    QString foreignAddress;
    QString status;
    QString pid;
    QString program;

    bool operator==(const ConnectionsData &other) const
    {
        return other.protocol == protocol
            && other.localAddress == localAddress
            && other.foreignAddress == foreignAddress
            && other.status == status
            && other.pid == pid
            && other.program == program;
    }
};

class ConnectionsModel : public QAbstractListModel
{
    Q_OBJECT

    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)

public:
    enum ConnectionsModelRoles { ProtocolRole = Qt::UserRole + 1, LocalAddressRole, ForeignAddressRole, StatusRole, PidRole, ProgramRole };
    Q_ENUM(ConnectionsModelRoles)

    explicit ConnectionsModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    bool busy() const;

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void start();
    Q_INVOKABLE void stop();

signals:
    void countChanged();
    void busyChanged();
    void showErrorMessage(const QString &message);

protected slots:
    void refreshConnections(const  QVector<QStringList>& results);

private:
    QVector<ConnectionsData> m_connectionsData;
    QTimer timer;
    bool m_busy = false;
    NetstatHelper m_netstatHelper;
};

#endif // CONECTIONSMODEL_H
