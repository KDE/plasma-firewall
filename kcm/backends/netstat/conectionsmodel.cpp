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

#include "netstatclient.h"

ConnectionsModel::ConnectionsModel(QObject *parent)
    : QAbstractListModel(parent), m_queryRunning(false)
    , m_queryAction(KAuth::Action(QStringLiteral("org.kde.netstat.query")))
{
    m_queryAction.setHelperId("org.kde.netstat");

    connect(&timer, &QTimer::timeout, this, &ConnectionsModel::refreshConnections);
    timer.setInterval(30000);
    timer.start();


    QTimer::singleShot(200, this, &ConnectionsModel::refreshConnections);
}

int ConnectionsModel::rowCount(const QModelIndex &parent) const
{
    // For list models only the root node (an invalid parent) should return the list's size. For all
    // other (valid) parents, rowCount() should return 0 so that it does not become a tree model.
    if (parent.isValid())
        return 0;

    return m_connectionsData.size();
}

QVariant ConnectionsModel::data(const QModelIndex &index, int role) const
{
    const auto checkIndexFlags = QAbstractItemModel::CheckIndexOption::IndexIsValid
                               | QAbstractItemModel::CheckIndexOption::ParentIsInvalid;

    if (!checkIndex(index, checkIndexFlags)) {
        return {};
    }

    ConnectionsData data = m_connectionsData.at(index.row());
    switch(role) {
        case ProtocolRole: return data.protocol;
        case LocalAddressRole: return data.localAddress;
        case ForeignAddressRole: return data.foreignAddress;
        case StatusRole: return data.status;
        case PidRole: return data.pid;
        case ProgramRole: return data.program;
    }
    return {};
}

QVariant ConnectionsModel::data2(int row, const QByteArray &roleName) const
{
    const auto keys = roleNames().keys(roleName);
    if (keys.empty()) {
        return {};
    }
    return data(createIndex(row, 0), keys.first());
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
    if (m_queryRunning)
    {
        NetstatClient::self()->setStatus("Netstat client is bussy");
        return;
    }

    m_queryRunning = true;

    KAuth::ExecuteJob *job = m_queryAction.execute();
    connect(job, &KAuth::ExecuteJob::finished, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);
        if (!job->error())
        {
            beginResetModel();
            m_connectionsData.clear();
            for (const auto connection : job->data().value("connections", QVariantList()).toList()) {
                const auto connList = connection.toList();
                qDebug() << connList;
                ConnectionsData conn {
                    .protocol = connList.at(0).toString(),
                    .localAddress = connList.at(1).toString(),
                    .foreignAddress = connList.at(2).toString(),
                    .status = connList.at(3).toString(),
                    .pid = connList.at(4).toString(),
                    .program = connList.at(5).toString()
                };
                m_connectionsData.append(conn);
            }
            endResetModel();
            NetstatClient::self()->setStatus({});
        } else {
            NetstatClient::self()->setStatus(QStringLiteral("BACKEND ERROR: ") + job->error() + QStringLiteral(" ") + job->errorText());
        }
        m_queryRunning = false;
    });

    job->start();
}

