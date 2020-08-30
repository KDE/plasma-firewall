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

#include "ifirewallclientbackend.h"

IFirewallClientBackend::IFirewallClientBackend(QObject *parent, const QVariantList &)
    : QObject(parent) {};

void IFirewallClientBackend::setProfiles(const QVector<Entry> &profiles)
{
    m_profiles = profiles;
    std::sort(std::begin(m_profiles), std::end(m_profiles));
}

Entry IFirewallClientBackend::profileByName(const QString &name)
{
    auto it = std::find_if(std::begin(m_profiles), std::end(m_profiles),
                [&name](const Entry &entry) { return entry.name == name; });

    if (it != std::end(m_profiles)) {
        return *it;
    }

    return Entry({});
}

FirewallClient::Capabilities IFirewallClientBackend::capabilities() const
{
    return FirewallClient::None;
};

// just implement it when needed.
KJob *IFirewallClientBackend::save()
{
    return nullptr;
};
