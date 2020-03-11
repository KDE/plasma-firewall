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
        logsAutoRefresh: !isCurrentPage
    }

    NetstatClient {
        id: netStatClient
    }

    Kirigami.OverlaySheet {
        id: drawer
        parent: root.parent

        RuleEdit {
            id: ruleEdit
            height: childrenRect.height
            implicitWidth: 30 * Kirigami.Units.gridUnit
            onAccept: drawer.close()
            defaultOutgoingPolicyRule: policyChoices[defaultOutgoingPolicy.currentIndex].data
            defaultIncomingPolicyRule: policyChoices[defaultIncomingPolicy.currentIndex].data
        }
    }

    header: ColumnLayout {
        id: columnLayout

        FirewallClientInlineMessages {
            Layout.fillWidth: true
            client: firewallClient
            enabled: isCurrentPage
        }

        FirewallInlineMessage {
            text: netStatClient.status
        }

        Kirigami.FormLayout {
            RowLayout {
                Kirigami.FormData.label: i18n("Firewall Status:")
                Kirigami.FormData.enabled: !firewallClient.busy

                QQC2.CheckBox {
                    id: enabledCheckBox
                    text: i18n("Enabled")
                    enabled: !firewallClient.busy

                    function bindCurrent() {
                        checked = Qt.binding(function() {
                            return firewallClient.enabled;
                        });
                    }
                    Component.onCompleted: bindCurrent()

                    onToggled: {
                        firewallClient.enabled = checked;
                        bindCurrent();
                    }
                }

                InlineBusyIndicator {
                    Layout.fillHeight: true
                    running: firewallClient.status === FirewallClient.Enabling || firewallClient.status === FirewallClient.Disabling
                }
            }

            RowLayout {
                Kirigami.FormData.label: i18n("Default Incoming Policy:")
                Kirigami.FormData.enabled: !firewallClient.busy

                QQC2.ComboBox {
                    id: defaultIncomingPolicy

                    model: policyChoices
                    textRole: "text"
                    enabled: !firewallClient.busy && firewallClient.enabled
                    QQC2.ToolTip.text:  policyChoices[currentIndex].tooltip
                    QQC2.ToolTip.delay: 1000
                    QQC2.ToolTip.timeout: 5000
                    QQC2.ToolTip.visible: hovered

                    function bindCurrent() {
                        currentIndex = Qt.binding(function() {
                            return policyChoices.findIndex((choice) => choice.data === firewallClient.defaultIncomingPolicy);
                        });
                    }
                    Component.onCompleted: bindCurrent()

                    onActivated: {
                        firewallClient.defaultIncomingPolicy = policyChoices[index].data;
                        bindCurrent();
                    }
                }

                InlineBusyIndicator {
                    Layout.fillHeight: true
                    running: firewallClient.status === FirewallClient.SettingDefaultIncomingPolicy
                }
            }

            RowLayout {
                Kirigami.FormData.label: i18n("Default Outgoing Policy:")
                Kirigami.FormData.enabled: !firewallClient.busy

                QQC2.ComboBox {
                    id: defaultOutgoingPolicy
                    model: policyChoices
                    textRole: "text"

                    enabled: !firewallClient.busy && firewallClient.enabled
                    QQC2.ToolTip.text:  policyChoices[currentIndex].tooltip
                    QQC2.ToolTip.delay: 1000
                    QQC2.ToolTip.timeout: 5000
                    QQC2.ToolTip.visible: hovered

                    function bindCurrent() {
                        currentIndex = Qt.binding(function() {
                            return policyChoices.findIndex((choice) => choice.data === firewallClient.defaultOutgoingPolicy);
                        });
                    }
                    Component.onCompleted: bindCurrent()

                    onActivated:  {
                        firewallClient.defaultOutgoingPolicy = policyChoices[index].data;
                        bindCurrent();
                    }
                }

                InlineBusyIndicator {
                    Layout.fillHeight: true
                    running: firewallClient.status === FirewallClient.SettingDefaultOutgoingPolicy
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
            model: firewallClient.rules()
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
                "firewallClient": firewallClient,
                "netStatClient" : netStatClient,
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
        InlineBusyIndicator {
            horizontalAlignment: Qt.AlignRight
            running: firewallClient.status === FirewallClient.AddingRule
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
