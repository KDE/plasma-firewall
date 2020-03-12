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

#include "netstatclient.h"

/* Access to the Netstat Client thru the Connections Model */
static NetstatClient *_self = nullptr;

NetstatClient* NetstatClient::self() {
    assert(_self);
    return _self;
}

NetstatClient::NetstatClient(QObject *parent)
    : QObject(parent)
    , m_connections(new ConnectionsModel(this))
{
    _self = this;
}

ConnectionsModel *NetstatClient::connectionsModel() const
{
    return m_connections;
}

void NetstatClient::setStatus(const QString& message)
{
    if (mStatus != message) {
        mStatus = message;
        Q_EMIT statusChanged(mStatus);
    }
}

QString NetstatClient::status() const
{
    return mStatus;
}
