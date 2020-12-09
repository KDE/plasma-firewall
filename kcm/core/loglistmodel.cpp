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

#include <QDebug>

// Regexp failed me, parsing it is.
std::map<QString, QString> parseString(const QString& line) {

    // We can find a line we are not interested.:
    // "-- Journal begins at Sun 2020-09-20 11:37:15 BST, ends at Wed 2020-12-09 18:45:16 GMT. --"
    if (line.startsWith("-- Journal begins at ")) {
        return {};
    }

// indices
// 0    1   2        3          4       5    6    7
// Dec 06 17:42:45 tomatoland kernel: [UFW BLOCK] IN=wlan0 OUT= MAC= SRC=192.168.50.181
// DST=224.0.0.252 LEN=56 TOS=0x00 PREC=0x00 TTL=255 ID=52151 PROTO=UDP SPT=5355 DPT=5355 LEN=36
//
// We are interested in the dates, (0, 1, 2), and then starting on 7.
    std::map<QString, QString> results;
    QStringList splited = line.split(' ');
    if (splited.size() < 7) {
        return {};
    }

    results["date"] = splited[0] + " " + splited[1];
    results["time"] = splited[3];

    // We can drop now everything up to 7.
    splited.erase(std::begin(splited), std::begin(splited) + 7);
    for (const QString& element : splited) {
        for (const QString& key : {"IN", "SRC", "DST", "PROTO", "STP", "DPT"}) {
            if (element.startsWith(key)) {
                results[key] = element.mid(element.indexOf('=')+1);
            }
        }
    }

    return results;
}

void LogListModel::addRawLogs(const QStringList &rawLogsList)
{
    QVector<LogData> newLogs;
    newLogs.reserve(rawLogsList.count());
    for (const QString &log : rawLogsList) {
        auto map = parseString(log);

        LogData logDetails {
            .sourceAddress = map["SRC"],
            .sourcePort = map["SPT"],
            .destinationAddress = map["DST"],
            .destinationPort = map["DPT"],
            .protocol = map["PROTO"],
            .interface = map["IN"],
            .action = "",
            .time = map["time"],
            .date = map["date"]
        };
        newLogs.append(logDetails);
    }

    if (!newLogs.isEmpty()) {
        beginInsertRows(QModelIndex(), rowCount(), rowCount() + newLogs.count() - 1);
        m_logsData << newLogs;
        endInsertRows();

        emit countChanged();
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
