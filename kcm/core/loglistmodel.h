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

#ifndef LOGLISTMODEL_H
#define LOGLISTMODEL_H

#include <QAbstractListModel>
#include <QVariantList>

struct LogData {
    QString sourceAddress;
    QString sourcePort;
    QString destinationAddress;
    QString destinationPort;
    QString protocol;
    QString interface;
    QString action;
    QString time;
    QString date;
};

class LogListModel : public QAbstractListModel
{
    Q_OBJECT

public:
    explicit LogListModel(QObject *parent = nullptr);

    enum LogItemModelRoles
    {
        SourceAddressRole = Qt::UserRole + 1,
        SourcePortRole,
        DestinationAddressRole,
        DestinationPortRole,
        ProtocolRole,
        InterfaceRole,
        ActionRole,
        TimeRole,
        DateRole,
    };


    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    Q_INVOKABLE QVariant data2(int row, const QByteArray &roleName) const;

    void addRawLogs(const QStringList &rawLogsList);
protected:
    QHash<int, QByteArray> roleNames() const override;

private:
    QVector<LogData> m_logsData;
};

#endif // LOGLISTMODEL_H
