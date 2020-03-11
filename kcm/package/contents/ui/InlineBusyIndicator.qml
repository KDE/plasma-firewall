/*
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
import QtQuick.Controls 2.9 as QQC2

import org.kde.kirigami 2.10 as Kirigami

Item {
    id: container

    property alias running: busyIndicator.running
    property int horizontalAlignment: Qt.AlignLeft

    implicitWidth: busyIndicator.implicitWidth
    // Not hiding the container so the layout doesn't shift as it comes and goes

    QQC2.BusyIndicator {
        id: busyIndicator
        anchors {
            left: container.horizontalAlignment === Qt.AlignLeft ? parent.left : undefined
            horizontalCenter: container.horizontalAlignment === Qt.AlignHCenter ? parent.horizontalCenter : undefined
            right: container.horizontalAlignment === Qt.AlignRight ? parent.right : undefined
            verticalCenter: parent.verticalCenter
        }
        width: height
        height: Kirigami.Units.iconSizes.medium
        visible: running
    }
}
