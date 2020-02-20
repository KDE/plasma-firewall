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
    // For list models only the root node (an invalid parent) should return the list's size. For all
    // other (valid) parents, rowCount() should return 0 so that it does not become a tree model.
    if (parent.isValid())
        return 0;

    return m_logsData.size();
}

QVariant LogListModel::data(const QModelIndex &index, int role) const
{
    const auto checkIndexFlags =  QAbstractItemModel::CheckIndexOption::IndexIsValid
                               | QAbstractItemModel::CheckIndexOption::ParentIsInvalid;

    if (!checkIndex(index, checkIndexFlags)) {
        return {};
    }

    if (index.row() >= 0 && index.row() < m_logsData.size()) {
        QVariantList logData = m_logsData[index.row()].toList();

        int valueIndex = role - (Qt::UserRole + 1);
        if (valueIndex < logData.size())
            return logData.value(valueIndex);
    }

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
    beginInsertRows(QModelIndex(), 0, rawLogsList.size() - 1);
    // UNSCAPED REGEX: (.*)\s(.*)\s(.*):\s\[(.*)\]\s\[(.*)\].*IN=([\w|\d]*).*SRC=([\w|\.|\d]*).*DST=([\w|\.|\d]*).*PROTO=([\w|\.|\d]*)\s(SPT=(\d*)\sDPT=(\d*))?.*
    static QRegularExpression regex(
        "(.*)\\s(.*)\\s(.*):\\s\\[(.*)\\]\\s\\[(.*)\\]"
        ".*IN=([\\w|\\d]*)"
        ".*SRC=([\\w|\\.|\\d]*)"
        ".*DST=([\\w|\\.|\\d]*)"
        ".*PROTO=([\\w|\\.|\\d]*)"
        "\\s(SPT=(\\d*)\\sDPT=(\\d*))?.*");

    for (const QString &log : rawLogsList) {

        auto match = regex.match(log);
        if (match.hasMatch()) {
            QDateTime date = QDateTime::fromString(match.captured(1), "MMM d HH:mm:ss");
            const QString host = match.captured(2);
            const QString id = match.captured(4);
            const QString action = match.captured(5);
            const QString interface = match.captured(6);
            const QString sourceAddress = match.captured(7);
            const QString destinationAddress = match.captured(8);
            const QString protocol = match.captured(9);
            const QString sourcePort = match.captured(11);
            const QString destinationPort = match.captured(12);

            QVariantList logDetails ({
                sourceAddress, sourcePort,
                destinationAddress, destinationPort,
                protocol, interface,
                action, date.toString("HH:mm:ss"), date.toString("MMM dd")
            });

            m_logsData.push_front((QVariant) logDetails);
        }
    }
    endInsertRows();
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
