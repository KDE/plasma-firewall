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

#ifndef NETSTATHELPER_H
#define NETSTATHELPER_H

#include <KAuth>
#include <QVariantMap>

using namespace KAuth;
class NetstatHelper : public QObject
{
    Q_OBJECT
public:
    NetstatHelper();

public Q_SLOTS:
    ActionReply query(const QVariantMap &map);

private:
    QVariantList parseOutput(const QByteArray &netstatOutput);
    QVariantList parseNetstatOutput(const QByteArray &netstatOutput);
    QVariantList parseSSOutput(const QByteArray &ss);

    QString extractAndStrip(const QString &src, const int &index, const int &size);

    /* Netstat has been deprecated for more than 20 years,
     * some distros such as arch linux use 'ss' as default.
     */
    int mHasSS;

    /* Distros are not obliged to install this. let's query it before
     * assuming that this actually exists */
    int mHasNetstat;
};

#endif // NETSTATHELPER_H
