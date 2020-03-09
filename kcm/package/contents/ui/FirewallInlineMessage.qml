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
import org.kde.kirigami 2.4 as Kirigami

Kirigami.InlineMessage {
    id: root
    type: Kirigami.MessageType.Information
    Layout.fillWidth: true
    visible: text.length != 0
    showCloseButton: true
    onTextChanged: {
        if (text.length != 0) {
            show();
        }
    }
}
