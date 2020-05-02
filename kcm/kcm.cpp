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


#include "kcm.h"

#include <KAboutData>
#include <KJob>
#include <KLocalizedString>
#include <KPluginFactory>
#include <KAboutData>

#include "version.h"
#include "core/rulelistmodel.h"
#include "core/loglistmodel.h"

#include "backends/netstat/netstatclient.h"
#include "backends/netstat/conectionsmodel.h"

K_PLUGIN_FACTORY_WITH_JSON(KCMFirewallFactory,
                           "kcm_firewall.json",
                           registerPlugin<KCMFirewall>(); )

KCMFirewall::KCMFirewall(QObject *parent, const QVariantList &args) :
    KQuickAddons::ConfigModule(parent, args), m_client(new FirewallClient(this))
{
    KAboutData* about = new KAboutData("kcm_firewall", i18n("Configure Firewall"),
                                       "0.1", QString(), KAboutLicense::GPL_V3);
    about->addAuthor("Alexis López Zubieta", QString(), "azubieta90@gmail.com");
    about->addAuthor("Tomaz Canabrava", QString(), "tcanabrava@kde.org");

    setAboutData(about);
    setButtons(Help);
    if (m_client->capabilities() & FirewallClient::SaveCapability) {
        setButtons(Help | Apply);
    }

    qmlRegisterAnonymousType<KJob>("org.kcm.firewall", 1);
    qmlRegisterType<RuleListModel>("org.kcm.firewall", 1, 0, "RuleListModel");
    qmlRegisterType<RuleWrapper>("org.kcm.firewall", 1, 0, "Rule");
    qmlRegisterUncreatableType<FirewallClient>("org.kcm.firewall", 1, 0, "FirewallClient", "FirewallClient is created by the KCM.");
    qmlRegisterUncreatableType<LogListModel>("org.kcm.firewall", 1, 0, "LogListModel", "Only created from the UfwClient.");
    qmlRegisterType<NetstatClient>("org.kcm.firewall", 1, 0, "NetstatClient");
    qmlRegisterUncreatableType<ConnectionsModel>("org.kcm.firewall", 1, 0, "ConnectionsModel", "Use the NetstatClient");
    
}

KCMFirewall::~KCMFirewall()
{

}

void KCMFirewall::save() {
     m_client->save();
}

FirewallClient *KCMFirewall::client() {
    return m_client;
}

#include "kcm.moc"
