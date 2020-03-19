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


#ifndef PROFILEITEMMODEL_H
#define PROFILEITEMMODEL_H

#include <QAbstractListModel>

#include "rulewrapper.h"
#include "profile.h"

class RuleListModel : public QAbstractListModel

{
    Q_OBJECT

public:
    enum ProfileItemModelRoles
    {
        ActionRole = Qt::UserRole + 1,
        FromRole,
        ToRole,
        Ipv6Role,
        LoggingRole
    };

    explicit RuleListModel(QObject *parent = nullptr);

    Q_INVOKABLE void move(int from, int to);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    void setProfile(Profile profile);
protected:
    QHash<int, QByteArray> roleNames() const override;

private:
    Profile m_profile;
    QVector<Rule> m_rules;
};

#endif // PROFILEITEMMODEL_H
