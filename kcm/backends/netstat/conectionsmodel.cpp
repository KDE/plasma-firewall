/*
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
 * Copyright 2020 Tomaz Canabrava <tcanabrava@kde.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License or (at your option) version 3 or any later version
 * accepted by the membership of KDE e.V. (or its successor approved
 * by the membership of KDE e.V.), which shall act as a proxy
 * defined in Section 14 of version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "conectionsmodel.h"

#include <QDebug>

#include <KLocalizedString>

#include "netstatclient.h"

ConnectionsModel::ConnectionsModel(QObject *parent)
    : QAbstractListModel(parent)
    , m_queryAction(KAuth::Action(QStringLiteral("org.kde.netstat.query")))
{
    m_queryAction.setHelperId("org.kde.netstat");

    connect(&timer, &QTimer::timeout, this, &ConnectionsModel::refreshConnections);
    timer.setInterval(30000);
    timer.start();

    QTimer::singleShot(0, this, &ConnectionsModel::refreshConnections);
}

bool ConnectionsModel::busy() const
{
    return m_busy;
}

void ConnectionsModel::setBusy(bool busy)
{
    if (m_busy != busy) {
        m_busy = busy;
        emit busyChanged();
    }
}

int ConnectionsModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }

    return m_connectionsData.size();
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
        return data.program;
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

void ConnectionsModel::refreshConnections()
{
    if (m_busy) {
        return;
    }

    setBusy(true);

    KAuth::ExecuteJob *job = m_queryAction.execute();
    connect(job, &KAuth::ExecuteJob::finished, this, [this, job] {
        setBusy(false);

        if (job->error()) {
            emit showErrorMessage(i18n("Failed to get connections: %1", job->errorString()));
            return;
        }

        const auto oldConnectionsData = m_connectionsData;
        QVector<ConnectionsData> newConnectionsData;

        beginResetModel();
        m_connectionsData.clear();
        for (const auto connection : job->data().value("connections", QVariantList()).toList()) {
            const auto connList = connection.toList();
            ConnectionsData conn {.protocol = connList.at(0).toString(),
                                  .localAddress = connList.at(1).toString(),
                                  .foreignAddress = connList.at(2).toString(),
                                  .status = connList.at(3).toString(),
                                  .pid = connList.at(4).toString(),
                                  .program = connList.at(5).toString()};
            newConnectionsData.append(conn);
        }

        if (newConnectionsData != oldConnectionsData) {
            beginResetModel();
            m_connectionsData = newConnectionsData;
            endResetModel();
        }

        if (newConnectionsData.count() != oldConnectionsData.count()) {
            emit countChanged();
        }
    });

    job->start();
}
