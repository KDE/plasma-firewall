// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#include "loglistmodel.h"

#include <QDateTime>
#include <QRegularExpression>

LogListModel::LogListModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

bool LogListModel::busy() const
{
    return m_busy;
}

void LogListModel::setBusy(bool busy)
{
    if (m_busy != busy) {
        m_busy = busy;
        emit busyChanged();
    }
}

int LogListModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }

    return m_logsData.size();
}

QVariant LogListModel::data(const QModelIndex &index, int role) const
{
    const auto checkIndexFlags = QAbstractItemModel::CheckIndexOption::IndexIsValid | QAbstractItemModel::CheckIndexOption::ParentIsInvalid;

    if (!checkIndex(index, checkIndexFlags)) {
        return {};
    }

    LogData data = m_logsData.at(index.row());
    switch (role) {
    case SourceAddressRole:
        return data.sourceAddress;
    case SourcePortRole:
        return data.sourcePort;
    case DestinationAddressRole:
        return data.destinationAddress;
    case DestinationPortRole:
        return data.destinationPort;
    case ProtocolRole:
        return data.protocol;
    case InterfaceRole:
        return data.interface;
    case ActionRole:
        return data.action;
    case TimeRole:
        return data.time;
    case DateRole:
        return data.date;
    };

    return {};
}

QHash<int, QByteArray> LogListModel::roleNames() const
{
    return {
        {SourceAddressRole, "sourceAddress"},
        {SourcePortRole, "sourcePort"},
        {DestinationAddressRole, "destinationAddress"},
        {DestinationPortRole, "destinationPort"},
        {ProtocolRole, "protocol"},
        {InterfaceRole, "interface"},
        {ActionRole, "action"},
        {TimeRole, "time"},
        {DateRole, "date"},
    };
}


void LogListModel::appendLogData(const QVector<LogData> newData)
{
    if (newData.isEmpty()) {
        return;
    }
    beginResetModel();
    m_logsData = newData;
    endResetModel();
    emit countChanged();
}
