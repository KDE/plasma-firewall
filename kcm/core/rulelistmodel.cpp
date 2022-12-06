// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#include "rulelistmodel.h"

RuleListModel::RuleListModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

void RuleListModel::move(int from, int to)
{
    if (to < 0 || to >= m_rules.count()) {
        return;
    }

    int newPos = to > from ? to + 1 : to;
    bool validMove = beginMoveRows(QModelIndex(), from, from, QModelIndex(), newPos);
    if (validMove) {
        m_rules.move(from, to);
        endMoveRows();
    }
}

int RuleListModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return m_rules.count();
}

QVariant RuleListModel::data(const QModelIndex &index, int role) const
{
    const auto checkIndexFlags = QAbstractItemModel::CheckIndexOption::IndexIsValid | QAbstractItemModel::CheckIndexOption::ParentIsInvalid;

    if (!checkIndex(index, checkIndexFlags)) {
        return {};
    }

    const Rule *rule = m_rules.at(index.row());

    switch (role) {
    case ActionRole:
        return rule->actionStr();
    case FromRole:
        return rule->fromStr();
    case ToRole:
        return rule->toStr();
    case Ipv6Role:
        return rule->ipv6() ? "IPv6" : "IPv4";
    case LoggingRole:
        return rule->loggingStr();
    }
    return {};
}

void RuleListModel::setProfile(const Profile &profile)
{
    qDebug() << "Profile on the model received. enabled? " << profile.enabled();

    beginResetModel();
    m_profile = profile;
    m_rules = m_profile.rules();
    endResetModel();
}

QHash<int, QByteArray> RuleListModel::roleNames() const
{
    return {
        {ActionRole, "action"},
        {FromRole, "from"},
        {ToRole, "to"},
        {Ipv6Role, "ipVersion"},
        {LoggingRole, "logging"},
    };
}
