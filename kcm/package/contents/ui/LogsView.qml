/*
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
 * Copyright 2020 Tomaz Canabrava <tcanabrava@kde.org>
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


import QtQuick 2.0
import QtQuick.Layouts 1.3
import QtQuick.Controls 2.12 as QQC2
import QtQuick.Controls 1.4 as QQC1
import org.kde.kirigami 2.10 as Kirigami

import org.kde.kcm 1.2 as KCM
import org.kcm.firewall 1.0

KCM.ScrollViewKCM {
    id: root
    property var firewallClient: null
    property int currentHoveredRow: -1

    property QtObject model: firewallClient.logsModel

    property QtObject currentJob: null

    title: i18n("Firewall Logs")

    /* TODO:
     *   onClicked: Qt.openUrlExternally(
     *               "https://www.geoiptool.com/?ip=%1".arg(model.sourceAddress))
     *   }
     */

    function blacklistRow(row) {
        const idx = root.model.index(row, 0);

        const roles = ["Protocol",
                       "SourceAddress",
                       "SourcePort",
                       "DestinationAddress",
                       "DestinationPort",
                       "Interface"];

        const args = roles.map((role) => {
            return role + "Role";
        }).map((role) => {
            return model.data(idx, LogListModel[role]);
        });

        const rule = firewallClient.createRuleFromLog(...args);

        const job = firewallClient.addRule(rule);
        currentJob = job;

        ruleCreationMessage.visible = false;

        job.result.connect(function() {
            currentJob = null;

            if (job.error) {
                if (job.error !== 4) { // FIXME magic number
                    ruleCreationMessage.type = Kirigami.MessageType.Error;
                    ruleCreationMessage.text = i18n("Error creating rule: %1", job.errorString);
                    ruleCreationMessage.visible = true;
                }
                return;
            }

            ruleCreationMessage.type = Kirigami.MessageType.Positive;
            ruleCreationMessage.text = i18n("Created a blacklist rule for this log entry.");
            ruleCreationMessage.visible = true;
        });
    }

    header: RowLayout {
        Kirigami.InlineMessage {
            id: logsModelError
            Layout.fillWidth: true
            type: Kirigami.MessageType.Error
            showCloseButton: true

            Connections {
                target: root.model
                onShowErrorMessage: {
                    logsModelError.text = message;
                    logsModelError.visible = true;
                }
            }
        }

        Kirigami.InlineMessage {
            id: ruleCreationMessage
            Layout.fillWidth: true
            showCloseButton: true
        }
    }

    view: Flickable {
        QQC1.TableView {
            id: tableView
            anchors.fill: parent
            activeFocusOnTab: true
            // Would be nice to support multi-selection
            //selectionMode: QQC1.SelectionMode.ExtendedSelection

            // TODO let Delete key add rule?

            QQC2.BusyIndicator {
                anchors.centerIn: parent
                // Show busy spinner only on initial population and not while an error is shown
                running: tableView.model.count === 0 && tableView.model.busy && !logsModelError.visible
            }

            model: root.model
            QQC1.TableViewColumn {
                title: i18n("Protocol")
                role: "protocol"
                width: Kirigami.Units.gridUnit * 3
            }
            QQC1.TableViewColumn {
                title: i18n("From")
                role: "sourceAddress"
                width: Kirigami.Units.gridUnit * 10
            }
            QQC1.TableViewColumn {
                role: "sourcePort"
                width: Kirigami.Units.gridUnit * 3
            }
            QQC1.TableViewColumn {
                title: i18n("To")
                role: "destinationAddress"
                width: Kirigami.Units.gridUnit * 10
            }
            QQC1.TableViewColumn {
                role: "destinationPort"
                width: Kirigami.Units.gridUnit * 3
            }
            QQC1.TableViewColumn {
                title: i18n("Interface")
                role: "interface"
                width: Kirigami.Units.gridUnit * 3
            }
        }
    }

    footer: RowLayout {
        Item {
            Layout.fillWidth: true
        }

        InlineBusyIndicator {
            horizontalAlignment: Qt.AlignRight
            running: root.currentJob
        }

        QQC2.Button {
            text: i18n("Blacklist Connection")
            icon.name: "network-disconnect"
            // HACK TableView lets us select a fake zero index when view is empty...
            enabled: tableView.selection.count > 0 && model.count > 0 && !root.currentJob
            onClicked: blacklistRow(tableView.selection.forEach(blacklistRow))
        }
    }
}
