// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

import QtQml 2.12
import QtQuick 2.12
import QtQuick.Layouts 1.3
import QtQuick.Controls 2.12 as QQC2
import QtQuick.Controls 1.4 as QQC1
import org.kde.kirigami 2.12 as Kirigami

import org.kde.kcm 1.2 as KCM
import org.kde.kitemmodels 1.0
import org.kcm.firewall 1.0

KCM.ScrollViewKCM {
    id: root
    title: i18n("About")

    header: Kirigami.FormLayout {
        QQC2.Label {
            Kirigami.FormData.label: i18n("Firewall backend:")
            text: kcm.client.name
        }
    }
}
