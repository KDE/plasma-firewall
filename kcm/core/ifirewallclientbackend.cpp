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

IFirewallClientBackend::IFirewallClientBackend(FirewallClient *parent)
    : m_parent(parent)
{

};

FirewallClient *IFirewallClientBackend::parentClient() const
{
    return m_parent;
}

void IFirewallClientBackend::setProfiles(const QList<Entry> &profiles)
{
    std::sort(std::begin(m_profiles), std::end(m_profiles));
    m_profiles = profiles;
}

Entry IFirewallClientBackend::profileByName(const QString &name)
{
    for(const auto entry : qAsConst(m_profiles)) {
        if (entry.name == name) {
            return entry;
        }
    }
    return Entry({});
}
