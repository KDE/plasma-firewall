// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

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
        // HACK. Firefox reports as MainThread
        if (data.program == "MainThread") {
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

            if (conn.status == "UNCONN") {
                conn.status = i18n("Not Connected");
            } else if (conn.status == "ESTAB") {
                conn.status = i18n("Established");
            } else if (conn.status == "LISTEN") {
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
            emit countChanged();
        }
    });

    job->start();
}
