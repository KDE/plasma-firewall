// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#ifndef KCM_H
#define KCM_H

#include "core/firewallclient.h"
#include <KQuickAddons/ConfigModule>

class KCMFirewall : public KQuickAddons::ConfigModule
{
    Q_OBJECT
    Q_PROPERTY(FirewallClient *client READ client CONSTANT)

public:
    explicit KCMFirewall(QObject *parent, const QVariantList &args);

    ~KCMFirewall();
    void save() override;
    FirewallClient *client() const;

private:
    FirewallClient *const m_client;
};

#endif
