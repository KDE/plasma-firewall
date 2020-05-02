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


import QtQuick 2.6
import QtQuick.Layouts 1.3
import QtQuick.Controls 2.9 as QQC2
import QtQuick.Controls 1.4 as QQC1 // for Table View.

import org.kde.kcm 1.2 as KCM
import org.kcm.firewall 1.0

import org.kde.kirigami 2.10 as Kirigami


KCM.ScrollViewKCM {
    id: root

    implicitHeight: Kirigami.Units.gridUnit * 25
    implicitWidth: Kirigami.Units.gridUnit * 44

    KCM.ConfigModule.quickHelp: i18n("This module lets you configure firewall.")
    
    property var policyChoices : [
        {text: i18n("Allow"), data: "allow", tooltip: i18n("Allow all connections")},
        {text: i18n("Ignore"), data: "deny", tooltip: i18n("Keeps the program waiting until the connection attempt times out, some short time later.")},
        {text: i18n("Reject"), data: "reject", tooltip: i18n("Produces an immediate and very informative 'Connection refused' message")}
    ]

    Kirigami.OverlaySheet {
        id: drawer
        parent: root.parent
        onSheetOpenChanged: {
            if (sheetOpen) {
                ruleEdit.forceActiveFocus();
            } else {
                // FIXME also reset rule
                ruleEditMessage.visible = false;
            }
        }

        ColumnLayout {
            Kirigami.Heading {
                Layout.fillWidth: true
                text: ruleEdit.newRule ? i18n("Create New Firewall Rule") : i18n("Edit Firewall Rule")
            }

            Kirigami.InlineMessage {
                id: ruleEditMessage
                type: Kirigami.MessageType.Error
                Layout.fillWidth: true
            }

            RuleEdit {
                id: ruleEdit
                client: kcm.client
                height: childrenRect.height
                implicitWidth: 30 * Kirigami.Units.gridUnit

                Keys.onEnterPressed: Keys.onReturnPressed(event)
                Keys.onReturnPressed: {
                    if (drawer.sheetOpen) {
                        accepted();
                    } else { // FIXME OverlaySheet should lose focus once hidden
                        event.accepted = false;
                    }
                }
                Keys.onEscapePressed: {
                    if (drawer.sheetOpen) {
                        drawer.close()
                    } else {
                        event.accepted = false;
                    }
                }

                onAccepted:  {
                    var job = kcm.client[newRule ? "addRule" : "updateRule"](rule);
                    busy = true;
                    kcm.needsSave = true;
                    job.result.connect(function() {
                        busy = false;

                        if (job.error) {
                            // don't show an error when user canceled...
                            if (job.error !== 4) { // FIXME magic number
                                if (newRule) {
                                    ruleEditMessage.text = i18n("Error creating rule: %1", job.errorString);
                                } else {
                                    ruleEditMessage.text = i18n("Error updating rule: %1", job.errorString);
                                }
                                ruleEditMessage.visible = true;
                                
                            }
                            // ...but also don't close in this case!
                            return;
                        }
                        
                        drawer.close();
                        
                    });
                }
            }
        }
    }

    header: ColumnLayout {
        id: columnLayout

        Kirigami.InlineMessage {
            id: firewallInlineErrorMessage
            Layout.fillWidth: true
            type: Kirigami.MessageType.Error
        }

        Kirigami.FormLayout {
            RowLayout {
                Kirigami.FormData.label: i18n("Firewall Status:")
                Kirigami.FormData.enabled: enabledCheckBox.enabled

                QQC2.CheckBox {
                    id: enabledCheckBox
                    property QtObject activeJob: null
                    text: i18n("Enabled")
                    enabled: !activeJob

                    function bindCurrent() {
                        checked = Qt.binding(function() {
                            return kcm.client.enabled;
                        });
                    }
                    Component.onCompleted: bindCurrent()

                    onToggled: {
                        const enable = checked; // store the state on job begin, not when it finished

                        const job = kcm.client.setEnabled(checked);
                        enabledCheckBox.activeJob = job;
                        job.result.connect(function () {
                            enabledCheckBox.activeJob = null; // need to explicitly unset since gc will clear it non-deterministic
                            bindCurrent();

                            if (job.error && job.error !== 4) { // TODO magic number
                                if (enable) {
                                    firewallInlineErrorMessage.text = i18n("Error enabling firewall: %1", job.errorString)
                                } else {
                                    firewallInlineErrorMessage.text = i18n("Error disabling firewall: %1", job.errorString)
                                }
                                firewallInlineErrorMessage.visible = true;
                            }
                        });
                    }
                }

                InlineBusyIndicator {
                    Layout.fillHeight: true
                    running: enabledCheckBox.activeJob !== null
                }
            }

            Repeater {
                model: [
                    {label: i18n("Default Incoming Policy:"), key: "Incoming"},
                    {label: i18n("Default Outgoing Policy:"), key: "Outgoing"}
                ]

                RowLayout {
                    Kirigami.FormData.label: modelData.label
                    Kirigami.FormData.enabled: policyCombo.enabled

                    QQC2.ComboBox {
                        id: policyCombo

                        property QtObject activeJob: null
                        // TODO currentValue
                        readonly property string currentPolicy: policyChoices[currentIndex].data

                        model: policyChoices
                        textRole: "text"
                        enabled: !activeJob && kcm.client.enabled
                        QQC2.ToolTip.text: policyChoices[currentIndex].tooltip
                        QQC2.ToolTip.delay: 1000
                        QQC2.ToolTip.timeout: 5000
                        QQC2.ToolTip.visible: hovered

                        Binding { // :(
                            target: ruleEdit
                            property: "default" + modelData.key + "PolicyRule"
                            value: policyCombo.currentPolicy
                        }

                        function bindCurrent() {
                            currentIndex = Qt.binding(function() {
                                return policyChoices.findIndex((choice) => choice.data === kcm.client["default" + modelData.key + "Policy"]);
                            });
                        }
                        Component.onCompleted: bindCurrent()

                        onActivated: {
                            const job = kcm.client["setDefault" + modelData.key + "Policy"](currentPolicy)
                            policyCombo.activeJob = job;
                            job.result.connect(function () {
                                policyCombo.activeJob = null;
                                bindCurrent();

                                if (job.error && job.error !== 4) { // TODO magic number
                                    firewallInlineErrorMessage.text = i18n("Error changing policy: %1", job.errorString)
                                    firewallInlineErrorMessage.visible = true;
                                }
                            });
                        }
                    }

                    InlineBusyIndicator {
                        Layout.fillHeight: true
                        running: policyCombo.activeJob !== null
                    }
                }
            }
        }
    }

    // Hack, TableView can't be in the 'view' as it's not flickable.
    view: Flickable  {
        QQC1.TableView {
            id: tableView
            property int currentHoveredRow: -1

            anchors.fill: parent
            model: kcm.client.rulesModel
            enabled: kcm.client.enabled
            // ScrollViewKCM does its own frame
            frameVisible: false

            function editRule(row) {
                ruleEdit.rule = kcm.client.getRule(row);
                ruleEdit.newRule = false;
                drawer.open();
            }

            onDoubleClicked: editRule(row)
            Keys.onEnterPressed: Keys.onReturnPressed(event)
            Keys.onReturnPressed: {
                if (tableView.selection.count === 1) {
                    tableView.selection.forEach(editRule);
                    event.accepted = true;
                }
            }

            rowDelegate: MouseArea {
                height: Kirigami.Units.gridUnit + 2 * Kirigami.Units.smallSpacing // fit action buttons
                hoverEnabled: true
                acceptedButtons: Qt.NoButton
                onEntered: tableView.currentHoveredRow = styleData.row

                // Restore upstream TableView background...
                BorderImage {
                    visible: styleData.selected || styleData.alternate
                    source: "image://__tablerow/" + (styleData.alternate ? "alternate_" : "")
                            + (styleData.selected ? "selected_" : "")
                            + (tableView.activeFocus ? "active" : "")
                    anchors.fill: parent
                }
            }

            Kirigami.Heading {
                anchors.fill: parent
                text: i18n("No firewall rules have been added.")
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                enabled: false
                level: 3
                visible: tableView.rowCount === 0
            }

            QQC1.TableViewColumn {
                title: i18n("Action")
                role: "action"
                width: Kirigami.Units.gridUnit * 8
            }
            QQC1.TableViewColumn {
                title: i18n("From")
                role: "from"
                width: Kirigami.Units.gridUnit * 10
            }
            QQC1.TableViewColumn {
                title: i18n("To")
                role: "to"
                width: Kirigami.Units.gridUnit * 10
            }
            QQC1.TableViewColumn {
                title: i18n("Ip")
                role: "ipVersion"
                width: Kirigami.Units.gridUnit * 4
            }
            QQC1.TableViewColumn {
                title: i18n("Logging")
                role: "logging"
                width: Kirigami.Units.gridUnit * 5
            }

            QQC1.TableViewColumn {
                width: Kirigami.Units.iconSizes.small * 6
                resizable: false
                delegate: RowLayout {
                    id: ruleActionsRow
                    property QtObject activeJob: null
                    spacing: 0
                    // TODO InlineBusyIndicator?
                    enabled: !activeJob
                    visible: tableView.currentHoveredRow === styleData.row || tableView.selection.contains(styleData.row)

                    Item {
                        Layout.fillWidth: true
                    }

                    QQC2.ToolButton {
                        Layout.fillHeight: true
                        icon.name: "edit-entry"
                        onClicked: tableView.editRule(styleData.row)
                        QQC2.ToolTip {
                            text: i18nc("@info:tooltip", "Edit Rule")
                        }
                    }
                    QQC2.ToolButton {
                        Layout.fillHeight: true
                        icon.name: "edit-delete"
                        onClicked: {
                            const job = kcm.client.removeRule(styleData.row);
                            ruleActionsRow.activeJob = job;
                            kcm.needsSave = true;
                            job.result.connect(function () {
                                ruleActionsRow.activeJob = null;

                                if (job.error && job.error !== 4) { // TODO magic number
                                    firewallInlineErrorMessage.text = i18n("Error removing rule: %1", job.errorString);
                                    firewallInlineErrorMessage.visible = true;
                                }
                                
                            });
                        }
                        QQC2.ToolTip {
                            text: i18nc("@info:tooltip", "Remove Rule")
                        }
                    }
                }
            }
        }
    }

    footer: RowLayout {
        QQC2.Button {
            text: i18n("Connections...")
            icon.name: "network-connect"
            onClicked: kcm.push("ConnectionsView.qml", {
                "kcm.client": kcm.client
            });
        }
        QQC2.Button {
            text: i18n("Logs...")
            icon.name: "viewlog"
            onClicked: kcm.push("LogsView.qml", {
                "kcm.client": kcm.client,
            });
        }
        Item {
            Layout.fillWidth: true
        }
        
        QQC2.Button {
            enabled: !kcm.client.busy && kcm.client.enabled
            icon.name: "list-add"
            text: i18n("Add Rule")
            onClicked: {
                ruleEdit.newRule = true
                drawer.open()
            }
        }
    }
}
