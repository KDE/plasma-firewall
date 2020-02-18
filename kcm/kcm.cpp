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
#include <KLocalizedString>
#include <KPluginFactory>
#include <KAboutData>

#include "version.h"
#include "core/rulelistmodel.h"
#include "core/loglistmodel.h"
#include "core/firewallclient.h"

#include "backends/netstat/netstatclient.h"
#include "backends/netstat/conectionsmodel.h"

K_PLUGIN_FACTORY_WITH_JSON(KCMFirewallFactory,
                           "kcm_firewall.json",
                           registerPlugin<KCMFirewall>(); )

KCMFirewall::KCMFirewall(QObject *parent, const QVariantList &args) :
    KQuickAddons::ConfigModule(parent, args)
{
    KAboutData* about = new KAboutData("kcm_firewall", i18n("Configure Firewall"),
                                       "0.1", QString(), KAboutLicense::GPL_V3);
    about->addAuthor("Alexis López Zubieta", QString(), "azubieta90@gmail.com");
    about->addAuthor("Tomaz Canabrava", QString(), "tcanabrava@kde.org");

    setAboutData(about);
    setButtons(Help | Apply);

    qmlRegisterType<FirewallClient>("org.kcm.firewall", 1, 0, "FirewallClient");
    qmlRegisterType<RuleListModel>("org.kcm.firewall", 1, 0, "RuleListModel");
    qmlRegisterType<RuleWrapper>("org.kcm.firewall", 1, 0, "Rule");
    qmlRegisterUncreatableType<LogListModel>("org.kcm.firewall", 1, 0, "LogListModel", "Only created from the UfwClient.");
    qmlRegisterType<NetstatClient>("org.kcm.firewall", 1, 0, "NetstatClient");
    qmlRegisterUncreatableType<ConnectionsModel> ("org.kcm.firewall", 1,9, "ConnectionsModel", "Use the NetstatClient");
}

KCMFirewall::~KCMFirewall()
{

}

#include "kcm.moc"
