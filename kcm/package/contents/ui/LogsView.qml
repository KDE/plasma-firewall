/*
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
 * Copyright 2020 Tomaz Canabrava <tcanabrava@kde.org>
 * Copyright 2020 Kai Uwe Broulik <kde@broulik.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License or (at your option) version 3 or any later version
 * accepted by the membership of KDE e.V. (or its successor approved
 * by the membership of KDE e.V.), which shall act as a proxy
 * defined in Section 14 of version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


import QtQuick 2.12

import org.kde.kirigami 2.10 as Kirigami

import org.kcm.firewall 1.0

ViewBase {
    title: i18n("Firewall Logs")

    model: firewallClient.logsModel
    roles: [
        {title: i18n("Protocol"), role: "protocol", width: Kirigami.Units.gridUnit * 3},
        {title: i18n("From"), role: "sourceAddress", width: Kirigami.Units.gridUnit * 10},
        {title: "", role: "sourcePort", width: Kirigami.Units.gridUnit * 3},
        {title: i18n("To"), role: "destinationAddress", width: Kirigami.Units.gridUnit * 10},
        {title: "", role: "destinationPort", width: Kirigami.Units.gridUnit * 3},
        {title: i18n("Interface"), role: "interface", width: Kirigami.Units.gridUnit * 3}
    ]
    emptyListText: i18n("There are currently no firwall log entries.")

    blacklistRuleFactory: firewallClient.createRuleFromLog
    blacklistRuleRoleNames: [
        "Protocol",
        "SourceAddress",
        "SourcePort",
        "DestinationAddress",
        "DestinationPort",
        "Interface"
    ]
    blacklistRuleSuccessMessage: i18n("Created a blacklist rule from this log entry.");

    filterRoleNames: blacklistRuleRoleNames
}
