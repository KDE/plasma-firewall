/*
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
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

#ifndef LOGLISTMODEL_H
#define LOGLISTMODEL_H

#include <QAbstractListModel>
#include <QVariantList>

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
    QVariantList m_logsData;
};

#endif // LOGLISTMODEL_H
