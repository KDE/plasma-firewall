// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#include "conectionsmodel.h"

#include <QDebug>

#include <KLocalizedString>

#include "netstatclient.h"

ConnectionsModel::ConnectionsModel(QObject *parent)
    : QAbstractListModel(parent)
{
    connect(&m_netstatHelper, &NetstatHelper::queryFinished, this, &ConnectionsModel::refreshConnections);
    connect(&timer, &QTimer::timeout, &m_netstatHelper, &NetstatHelper::query);
    timer.setInterval(10500);
}

void ConnectionsModel::start()
{
    m_busy = true;
    Q_EMIT busyChanged();
    timer.start();
    QTimer::singleShot(0, &m_netstatHelper, &NetstatHelper::query);
}

void ConnectionsModel::stop()
{
    timer.stop();
}

int ConnectionsModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }

    return m_connectionsData.size();
}

bool ConnectionsModel::busy() const
{
    return m_busy;
}

QVariant ConnectionsModel::data(const QModelIndex &index, int role) const
{
    const auto checkIndexFlags = QAbstractItemModel::CheckIndexOption::IndexIsValid | QAbstractItemModel::CheckIndexOption::ParentIsInvalid;

    if (!checkIndex(index, checkIndexFlags)) {
        return {};
    }

    ConnectionsData data = m_connectionsData.at(index.row());
    switch (role) {
    case ProtocolRole:
        return data.protocol;
    case LocalAddressRole:
        return data.localAddress;
    case ForeignAddressRole:
        return data.foreignAddress;
    case StatusRole:
        return data.status;
    case PidRole:
        return data.pid;
    case ProgramRole:
        // HACK. Firefox reports as MainThread
        if (data.program == QLatin1String("MainThread")) {
            return "Firefox";
        } else {
            return data.program;
        }
    }
    return {};
}

QHash<int, QByteArray> ConnectionsModel::roleNames() const
{
    return {
        {ProtocolRole, "protocol"},
        {LocalAddressRole, "localAddress"},
        {ForeignAddressRole, "foreignAddress"},
        {StatusRole, "status"},
        {PidRole, "pid"},
        {ProgramRole, "program"},
    };
}

void ConnectionsModel::refreshConnections(const QList<QStringList> &result)
{
    if (m_netstatHelper.hasError()) {
        Q_EMIT showErrorMessage(i18n("Failed to get connections: %1", m_netstatHelper.errorString()));
        return;
    }

    const auto oldConnectionsData = m_connectionsData;
    QList<ConnectionsData> newConnectionsData;

    beginResetModel();
    m_connectionsData.clear();
    for (const auto &connection : result) {
        ConnectionsData conn{.protocol = connection.at(0),
                             .localAddress = connection.at(1),
                             .foreignAddress = connection.at(2),
                             .status = connection.at(3),
                             .pid = connection.at(4),
                             .program = connection.at(5)};

        if (conn.status == QLatin1String("UNCONN")) {
            conn.status = i18n("Not Connected");
        } else if (conn.status == QLatin1String("ESTAB")) {
            conn.status = i18n("Established");
        } else if (conn.status == QLatin1String("LISTEN")) {
            conn.status = i18n("Listening");
        }

        newConnectionsData.append(conn);
    }

    if (newConnectionsData != oldConnectionsData) {
        beginResetModel();
        m_connectionsData = newConnectionsData;
        endResetModel();
    }

    if (newConnectionsData.count() != oldConnectionsData.count()) {
        Q_EMIT countChanged();
    }

    if (m_busy) {
        m_busy = false;
        Q_EMIT busyChanged();
    }
}
