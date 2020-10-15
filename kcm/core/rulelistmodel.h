// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#pragma once

#include <kcm_firewall_core_export.h>

#include <QAbstractListModel>

#include "profile.h"
#include "rulewrapper.h"

class KCM_FIREWALL_CORE_EXPORT RuleListModel : public QAbstractListModel
{
    Q_OBJECT

public:
    enum ProfileItemModelRoles { ActionRole = Qt::UserRole + 1, FromRole, ToRole, Ipv6Role, LoggingRole };

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
