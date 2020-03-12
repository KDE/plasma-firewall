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

    implicitHeight: Kirigami.Units.gridUnit * 22
    implicitWidth: Kirigami.Units.gridUnit * 44

    KCM.ConfigModule.quickHelp: i18n("This module lets you configure firewall.")

    property var policyChoices : [
        {text: i18n("Allow"), data: "allow", tooltip: i18n("Allow all connections")},
        {text: i18n("Ignore"), data: "deny", tooltip: i18n("Keeps the program waiting until the connection attempt times out, some short time later.")},
        {text: i18n("Reject"), data: "reject", tooltip: i18n("Produces an immediate and very informative 'Connection refused' message")}
    ]

    FirewallClient {
        id: firewallClient
        backend: "ufw"
        // TODO only when on logs page but Binding {} is broken in Qt 5.14+...
        logsAutoRefresh: !isCurrentPage
    }

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
            Kirigami.InlineMessage {
                id: ruleEditMessage
                type: Kirigami.MessageType.Error
                Layout.fillWidth: true
            }

            RuleEdit {
                id: ruleEdit
                client: firewallClient
                height: childrenRect.height
                implicitWidth: 30 * Kirigami.Units.gridUnit

                onAccepted:  {
                    var job = firewallClient[newRule ? "addRule" : "updateRule"](rule);
                    busy = true;
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
                            return firewallClient.enabled;
                        });
                    }
                    Component.onCompleted: bindCurrent()

                    onToggled: {
                        const enable = checked; // store the state on job begin, not when it finished

                        const job = firewallClient.setEnabled(checked);
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
                        enabled: !activeJob && firewallClient.enabled
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
                                return policyChoices.findIndex((choice) => choice.data === firewallClient["default" + modelData.key + "Policy"]);
                            });
                        }
                        Component.onCompleted: bindCurrent()

                        onActivated: {
                            const job = firewallClient["setDefault" + modelData.key + "Policy"](currentPolicy)
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
            width: parent.width
            height: parent.height
            model: firewallClient.rulesModel
            enabled: firewallClient.enabled
            property int currentHoveredRow: -1

            rowDelegate: MouseArea{
                id: mouseArea
                height: 50
                hoverEnabled: true
                onContainsMouseChanged: {
                    if (mouseArea.containsMouse) {
                        tableView.currentHoveredRow = model.row
                    }
                }
                onPressed: mouse.accepted = false
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
                    id: buttonLayout

                    visible: model ? tableView.currentHoveredRow === model.row : false
                    QQC2.ToolButton {
                        icon.name: "edit-entry"
                        onClicked: {
                            ruleEdit.rule = firewallClient.getRule(model.row)
                            ruleEdit.newRule = false
                            drawer.open()
                        }
                    }
                    QQC2.ToolButton {
                        icon.name: "edit-delete"
                        onClicked: {
                            // FIXME busy indicator and error reporting
                            firewallClient.removeRule(model.row)
                        }
                    }
                }
            }
        }
    }


    footer: RowLayout {
        QQC2.Button {
            text: i18n("Connections...")
            onClicked: kcm.push("ConnectionsView.qml", {
                "firewallClient": firewallClient
            });
        }
        QQC2.Button {
            text: i18n("Logs...")
            onClicked: kcm.push("LogsView.qml", {
                "firewallClient": firewallClient,
            });
        }
        Item {
            Layout.fillWidth: true
        }
        QQC2.Button {
            enabled: !firewallClient.busy && firewallClient.enabled
            icon.name: "list-add"
            text: i18n("Add Rule")
            onClicked: {
                ruleEdit.newRule = true
                drawer.open()
            }
        }
    }
}
