// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>


import QtQuick 2.12

import org.kde.kirigami 2.10 as Kirigami

import org.kcm.firewall 1.0

ViewBase {
    title: i18n("Firewall Logs")

    model: kcm.client.logsModel
    roles: [
        {title: i18n("Protocol"), role: "protocol", width: Kirigami.Units.gridUnit * 3},
        {title: i18n("From"), role: "sourceAddress", width: Kirigami.Units.gridUnit * 10},
        {title: "", role: "sourcePort", width: Kirigami.Units.gridUnit * 3},
        {title: i18n("To"), role: "destinationAddress", width: Kirigami.Units.gridUnit * 10},
        {title: "", role: "destinationPort", width: Kirigami.Units.gridUnit * 3},
        {title: i18n("Interface"), role: "interface", width: Kirigami.Units.gridUnit * 3}
    ]
    emptyListText: i18n("There are currently no firewall log entries.")

    blacklistRuleFactory: kcm.client.createRuleFromLog
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
