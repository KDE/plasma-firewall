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
import QtQuick.Controls 1.4

import QtQuick.Controls 2.12 as QQC2

import org.kde.kirigami 2.4 as Kirigami

Kirigami.BasicListItem {
    id: itemRoot

    property bool dropAreasVisible: false

    signal edit(int index)
    signal remove(int index)

    height: 42

    onClicked: edit(index)

    RowLayout {
        QQC2.Label {
            Layout.fillHeight: true
            Layout.leftMargin: 4
            text: model.action
        }
        QQC2.Label {
            text: model.from
        }
        QQC2.Label {
            text: model.to
        }
        QQC2.Label {
            text: model.logging
        }
        Item {
            visible: !eraseButton.visible
            width: eraseButton.width
            height: eraseButton.height
        }
        QQC2.ToolButton {
            id: eraseButton
            visible: itemRoot.hovered

            icon.name: "user-trash"
            onClicked: itemRoot.remove(index)
        }
        Item {
            Layout.fillWidth: true
        }
    }
}
