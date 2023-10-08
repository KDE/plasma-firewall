// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
// SPDX-FileCopyrightText: 2023 ivan tkachenko <me@ratijas.tk>

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import org.kcm.firewall

Kirigami.OverlaySheet {
    id: root

    // Name of backend module
    property string name

    // Version of backend module
    property string version

    focus: true

    header: Kirigami.Heading {
        text: i18n("About Firewall")
    }

    Kirigami.FormLayout {
        Layout.preferredWidth: Kirigami.Units.gridUnit * 25

        Kirigami.SelectableLabel {
            Kirigami.FormData.label: i18n("Backend:")
            Layout.fillWidth: true
            textFormat: TextEdit.PlainText
            text: root.name
        }

        Kirigami.SelectableLabel {
            Kirigami.FormData.label: i18n("Version:")
            Layout.fillWidth: true
            textFormat: TextEdit.PlainText
            text: root.version
        }
    }

    function refresh() {
        // name is a non-NOTIFYable property
        name = kcm.client.name;
        version = kcm.client.version();
    }

    Component.onCompleted: refresh()
}
