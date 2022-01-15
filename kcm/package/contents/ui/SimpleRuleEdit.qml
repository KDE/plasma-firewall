// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

import QtQuick 2.12
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.1

import QtQuick.Controls 2.12 as QQC2
import org.kde.kirigami 2.4 as Kirigami

import org.kcm.firewall 1.0 as Firewall

Kirigami.FormLayout {
    QQC2.ComboBox {
        id: policy
        Kirigami.FormData.label: i18n("Simple Rule Edit:")
        model: policyChoices
        textRole: "text"
        currentIndex: rule.policy == "" ? 0 : policyChoices.findIndex((policy) => policy.data == rule.policy)
        onActivated: rule.policy = policyChoices[index].data
    }
    QQC2.ComboBox {
        id: application
        Kirigami.FormData.label: i18n("Application:")
        model: kcm.client.knownApplications()
    }

    onVisibleChanged: {
        console.log("Triggering", kcm.client.knownApplications());
        application.model = kcm.client.knownApplications();
    }
}
