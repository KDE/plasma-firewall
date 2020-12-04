// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
// SPDX-FileCopyrightText: 2020 Kai Uwe Broulik <kde@broulik.de>

import QtQuick 2.12

import org.kde.kirigami 2.14 as Kirigami

import org.kcm.firewall 1.0

ViewBase {
    id: base
    title: i18n("Connections")

    model: netStatClient.connectionsModel
    roles: [
        {title: i18n("Protocol"), role: "protocol", width: Kirigami.Units.gridUnit * 4},
        {title: i18n("Local Address"), role: "localAddress", width: Kirigami.Units.gridUnit * 10},
        {title: i18n("Foreign Address"), role: "foreignAddress", width: Kirigami.Units.gridUnit * 10},
        {title: i18n("Status"), role: "status", width: Kirigami.Units.gridUnit * 5},
        {title: i18n("PID"), role: "pid", width: Kirigami.Units.gridUnit * 3},
        {title: i18n("Program"), role: "program", width: Kirigami.Units.gridUnit * 7}
    ]
    defaultSortRole: "program"
    emptyListText: i18n("There are currently no open connections.")

    blacklistRuleFactory: kcm.client.createRuleFromConnection
    blacklistRuleRoleNames: [
        "Protocol",
        "LocalAddress",
        "ForeignAddress",
        "Status"
    ]
    blacklistRuleSuccessMessage: i18n("Created a blacklist rule from this connection.");

    filterRoleNames: blacklistRuleRoleNames.concat(["Pid", "Program"])

    NetstatClient {
        id: netStatClient
        property bool active: base.Kirigami.ColumnView.inViewport
        
        function updateRunning() {
            if (active) {
                if (!netStatClient.hasSS) {
                    console.log("Netstat client without ss");
                    base.errorMessage.text = i18n("could not find iproute2 or net-tools packages installed.");
                    base.errorMessage.visible = true;
                } else {
                    netStatClient.connectionsModel.start();
                }
            } else {
                netStatClient.connectionsModel.stop();
            }
        }
        onActiveChanged: updateRunning()

        Component.onCompleted : {
            console.log("Netstat client completed.");
            if (netStatClient.hasSS) {
                console.log("Starting netstat client");
            }
            netStatClient.updateRunning();
        }
    }
}
