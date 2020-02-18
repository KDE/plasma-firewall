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

#include "rulelistmodel.h"

#include <QDebug>

RuleListModel::RuleListModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

void RuleListModel::move(int from, int to)
{
    if(to < 0 && to >= m_rules.count())
        return;

    int newPos = to > from ? to + 1 : to;
    bool validMove = beginMoveRows(QModelIndex(), from, from, QModelIndex(), newPos);
    if (validMove)
    {
        m_rules.move(from, to);
        endMoveRows();
    }
}

int RuleListModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return m_rules.count();
}

QVariant RuleListModel::data(const QModelIndex &index, int role) const
{
    if (index.row() < 0 || index.row() >= m_rules.count()) {
        return {};
    }

    const Rule rule = m_rules.at(index.row());

    switch(role) {
        case ActionRole: return rule.actionStr();
        case FromRole: return rule.fromStr();
        case ToRole: return rule.toStr();
        case Ipv6Role: return rule.getV6() ? "IPv6" : "IPv4";
        case LoggingRole: return rule.loggingStr();
    }
    return {};
}

QVariant RuleListModel::data2(int row, const QByteArray &roleName) const
{
    const auto keys = roleNames().keys(roleName);
    if (keys.empty()) {
        return {};
    }
    return data(createIndex(row, 0), keys.first());
}

void RuleListModel::setProfile(Profile profile)
{
    beginResetModel();
    m_profile = profile;
    m_rules = m_profile.getRules();
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
