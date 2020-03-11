/*
 * Copyright 2020 Tomaz Canabrava <tcanabrava@kde.org>
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
import QtQuick.Layouts 1.3
import QtQuick.Controls 2.9 as QQC2

import org.kcm.firewall 1.0

import org.kde.kirigami 2.10 as Kirigami

ColumnLayout {
    id: column

    property FirewallClient client

    //visible: firewallErrorMessage.visible || firewallSuccessMessage.visible

    Connections {
        target: column.client
        enabled: column.enabled && column.client !== null
        onShowSuccessMessage: {
            firewallSuccessMessage.text = message;
            firewallSuccessMessage.visible = true;
            firewallSuccessMessageTimer.restart();
        }
        onShowErrorMessage: {
            firewallErrorMessage.text = message;
            firewallErrorMessage.visible = true;
        }
    }

    Kirigami.InlineMessage {
        id: firewallErrorMessage
        Layout.fillWidth: true
        type: Kirigami.MessageType.Error
        visible: false
        showCloseButton: true
    }

    // TODO this should be a passive popup / toast
    Kirigami.InlineMessage {
        id: firewallSuccessMessage
        Layout.fillWidth: true
        type: Kirigami.MessageType.Positive
        visible: false

        Timer {
            id: firewallSuccessMessageTimer
            interval: 5000
            onTriggered: firewallSuccessMessage.visible = false
        }
    }
}
