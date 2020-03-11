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

#include "loglistmodel.h"

#include <QDebug>
#include <QDateTime>
#include <QRegularExpression>

LogListModel::LogListModel(QObject *parent)
    : QAbstractListModel(parent)
{
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
    const auto checkIndexFlags =  QAbstractItemModel::CheckIndexOption::IndexIsValid
                               | QAbstractItemModel::CheckIndexOption::ParentIsInvalid;

    if (!checkIndex(index, checkIndexFlags)) {
        return {};
    }

    LogData data = m_logsData.at(index.row());
    switch(role) {
        case SourceAddressRole: return data.sourceAddress;
        case SourcePortRole: return data.sourcePort;
        case DestinationAddressRole: return data.destinationAddress;
        case DestinationPortRole: return data.destinationPort;
        case ProtocolRole: return data.protocol;
        case InterfaceRole: return data.interface;
        case ActionRole: return data.action;
        case TimeRole: return data.time;
        case DateRole: return data.date;
    };

    return {};
}

QVariant LogListModel::data2(int row, const QByteArray &roleName) const
{
    const auto keys = roleNames().keys(roleName);
    if (keys.empty()) {
        return {};
    }
    return data(createIndex(row, 0), keys.first());
}

void LogListModel::addRawLogs(const QStringList &rawLogsList)
{
    static QRegularExpression regex(
        R"regex(
            "(.*)\s(.*)\s(.*):\s\[(.*)\]\s\[(.*)\]"
            ".*IN=([\w|\d]*)"
            ".*SRC=([\w|\.|\d]*)"
            ".*DST=([\w|\.|\d]*)"
            ".*PROTO=([\w|\.|\d]*)"
            "\s(SPT=(\d*)\sDPT=(\d*))?.*"
        ")regex"
    );

    QVector<LogData> newLogs;
    newLogs.reserve(rawLogsList.count());
    for (const QString &log : rawLogsList) {
        auto match = regex.match(log);
        qDebug() << "Adding log" << log;
        if (match.hasMatch()) {
            QDateTime date = QDateTime::fromString(match.captured(1), "MMM d HH:mm:ss");
            const QString host = match.captured(2);
            const QString id = match.captured(4);

            LogData logDetails {
                .sourceAddress = match.captured(7),
                .sourcePort = match.captured(11),
                .destinationAddress = match.captured(8),
                .destinationPort = match.captured(12),
                .protocol =  match.captured(9),
                .interface = match.captured(6),
                .action = match.captured(5),
                .time = date.toString("HH:mm:ss"),
                .date = date.toString("MMM dd")
            };
            newLogs.append(logDetails);
        }
    }

    if (!newLogs.isEmpty()) {
        beginInsertRows(QModelIndex(), rowCount(), rowCount() + newLogs.count() - 1);
        m_logsData << newLogs;
        endInsertRows();
    }
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
