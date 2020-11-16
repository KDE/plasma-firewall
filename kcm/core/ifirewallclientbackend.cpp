// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */
#include <KLocalizedString>
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

