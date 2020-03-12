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

import QtQml 2.12
import QtQuick 2.12
import QtQuick.Layouts 1.3
import QtQuick.Controls 2.12 as QQC2
import QtQuick.Controls 1.4 as QQC1
import org.kde.kirigami 2.10 as Kirigami

import org.kde.kcm 1.2 as KCM
import org.kcm.firewall 1.0

KCM.ScrollViewKCM {
    id: root

    property QtObject firewallClient: null

    property QtObject model
    property var roles: []

    property QtObject currentJob: null

    property var blacklistRuleFactory
    property var blacklistRuleRoleNames: []

    function blacklistRow(row) {
        const idx = root.model.index(row, 0);

        const roles = blacklistRuleRoleNames;

        // Can this be done generically? :(
        let modelType = null;
        if (root.model instanceof LogListModel) {
            modelType = LogListModel;
        } else if (root.model instanceof ConnectionsModel) {
            modelType = ConnectionsModel;
        }

        const args = roles.map((role) => {
            return model.data(idx, modelType[role + "Role"]);
        });

        const rule = blacklistRuleFactory(...args);

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
            id: modelErrorMessage
            Layout.fillWidth: true
            type: Kirigami.MessageType.Error
            showCloseButton: true

            Connections {
                target: root.model
                onShowErrorMessage: {
                    modelErrorMessage.text = message;
                    modelErrorMessage.visible = true;
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

            // TODO let Delete key add blacklist rule?

            QQC2.BusyIndicator {
                anchors.centerIn: parent
                // Show busy spinner only on initial population and not while an error is shown
                running: root.model.count === 0 && root.model.busy && !modelErrorMessage.visible
            }

            model: root.model

            Instantiator {
                model: root.roles
                delegate: QQC1.TableViewColumn {
                    title: modelData.title
                    role: modelData.role
                    width: modelData.width
                }
                onObjectAdded: tableView.addColumn(object);
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
