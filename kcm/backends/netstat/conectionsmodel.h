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

#ifndef CONECTIONSMODEL_H
#define CONECTIONSMODEL_H

#include <QAbstractListModel>
#include <QTimer>

#include <KAuth>

struct ConnectionsData {
    QString protocol;
    QString localAddress;
    QString foreignAddress;
    QString status;
    QString pid;
    QString program;
};

class ConnectionsModel : public QAbstractListModel
{
    Q_OBJECT
public:
    enum ConnectionsModelRoles
    {
        ProtocolRole = Qt::UserRole + 1,
        LocalAddressRole,
        ForeignAddressRole,
        StatusRole,
        PidRole,
        ProgramRole
    };

    explicit ConnectionsModel(QObject *parent = nullptr);

    // Basic functionality:
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    // Translate a Qml call into a proper data() call.
    Q_INVOKABLE QVariant data2(int row, const QByteArray &roleName) const;

    QHash<int, QByteArray> roleNames() const override;

protected slots:
    void refreshConnections();

private:
    bool m_queryRunning;
    QVector<ConnectionsData> m_connectionsData;
    KAuth::Action m_queryAction;
    QTimer timer;
};

#endif // CONECTIONSMODEL_H
