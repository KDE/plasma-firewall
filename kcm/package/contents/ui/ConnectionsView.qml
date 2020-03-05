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


import QtQuick 2.12
import QtQuick.Layouts 1.3
import QtQuick.Controls 2.12 as QQC2
import org.kde.kcm 1.2 as KCM
import org.kcm.firewall 1.0

// for TableView
import QtQuick.Controls 1.4 as QQC1

import org.kde.kirigami 2.4 as Kirigami

/* ScrollViewKCM does not work
 *
 * because TableView is not flickable */
KCM.ScrollViewKCM {
    id: root
    property var drawer: null
    property var firewallClient: null
    property var netStatClient: null
    property int currentHoveredRow: -1

    title: i18n("Connections")
    view: Flickable {
        QQC1.TableView {
            id: tableView
            width: parent.width
            height: parent.height

            rowDelegate: MouseArea{
                id: mouseArea
                height: 50
                hoverEnabled: true
                onContainsMouseChanged: {
                    if (mouseArea.containsMouse) {
                        root.currentHoveredRow = model.row
                    }
                }
                onPressed: mouse.accepted = false
            }

            model: netStatClient.connections()
            QQC1.TableViewColumn {
                title: i18n("Protocol")
                role: "protocol"
                width: 80
            }
            QQC1.TableViewColumn {
                title: i18n("Local Address")
                role: "localAddress"
            }
            QQC1.TableViewColumn {
                title: i18n("Foreign Address")
                role: "foreignAddress"
            }
            QQC1.TableViewColumn {
                title: i18n("Status")
                role: "status"
                width: 80
            }
            QQC1.TableViewColumn {
                title: i18n("PID")
                role: "pid"
                width: 50
            }
            QQC1.TableViewColumn {
                title: i18n("Program")
                width: 100
                role: "program"
            }

            QQC1.TableViewColumn {
                delegate: QQC2.ToolButton {
                    icon.name: "list-remove"
                    Layout.alignment: Qt.AlignRight
                    visible: model ? root.currentHoveredRow === model.row : false
                    onClicked: {
                        var protocol = tableView.model.data2(model.row, "protocol");
                        var localAddress = tableView.model.data2(model.row, "localAddress");
                        var foreignAddress = tableView.model.data2(model.row, "foreignAddress");
                        var status = tableView.model.data2(model.row, "status");

                        var rule = firewallClient.createRuleFromConnection(protocol, localAddress, foreignAddress, status)
                        firewallClient.addRule(rule);
                    }
                }
            }
        }
    }
}
