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
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.1

import QtQuick.Controls 2.12 as QQC2
import org.kde.kirigami 2.4 as Kirigami

import org.kcm.firewall 1.0 as Firewall

Kirigami.FormLayout {
    signal accept(var rule)
    signal reject()

    property var defaultOutgoingPolicyRule: null
    property var defaultIncomingPolicyRule: null

    property var rule: Firewall.Rule {
        policy: "deny"
        incoming: true
        logging: "none"
    }

    property var ruleChoices : [
        {text: i18n("None"), data: "none"},
        {text: i18n("New Connections"), data: "log"},
        {text: i18n("All Packets"), data: "log-all"}
    ]
    property bool newRule: false

    onAccept: {
        if (newRule)
            firewallClient.addRule(rule)
        else
            firewallClient.updateRule(rule)
    }

    QQC2.ComboBox {
        id: policy
        Kirigami.FormData.label: i18n("Policy:")
        model: policyChoices
        textRole: "text"
        currentIndex: policyChoices.arrayIndex((policy) => policy.data == rule.policy)
        onCurrentIndexChanged: rule.policy = policyChoices[currentIndex].data
    }

    RowLayout {
        Kirigami.FormData.label: i18n("Direction:")
        QQC2.RadioButton {
            id: incoming
            text: i18n("Incoming")
            icon.name: "arrow-down"
            checked: rule.incoming
            onClicked: rule.incoming = true
        }
        QQC2.RadioButton {
            text: i18n("Outgoing")
            icon.name: "arrow-up"
            checked: !rule.incoming
            onClicked: rule.incoming = false
        }
    }

    RowLayout {
        Kirigami.FormData.label: i18n("Source:")

        IpV4TextField {
            id: sourceAddress
            text: rule.sourceAddress
            Layout.preferredWidth: policy.width * 0.6

            onTextChanged: rule.sourceAddress = text
        }
        PortTextField{
            id: sourcePort
            Layout.preferredWidth: policy.width * 0.38
            text: rule.sourcePort
            onTextChanged: rule.sourcePort = text
        }
    }

    RowLayout {
        Kirigami.FormData.label: i18n("Destination:")

        IpV4TextField {
            id: destinationAddress
            text: rule.destinationAddress
            Layout.preferredWidth: policy.width * 0.6
            onTextChanged: rule.destinationAddress = text
        }
        PortTextField {
            id: destinationPort
            Layout.preferredWidth: policy.width * 0.38
            text: rule.destinationPort
            onTextChanged: rule.destinationPort = text
        }
    }

    QQC2.ComboBox {
        Kirigami.FormData.label: i18n("Protocol:")

        id: protocolCb

        model: firewallClient.getKnownProtocols()

        currentIndex: rule.protocol
        onCurrentIndexChanged: rule.protocol = currentIndex
    }
    QQC2.ComboBox {
        Kirigami.FormData.label: i18n("Interface:")

        id: interfaceCb

        model: firewallClient.getKnownInterfaces()

        currentIndex: rule.interface
        onCurrentIndexChanged: rule.interface = currentIndex

    }

    QQC2.ComboBox {
        Kirigami.FormData.label: i18n("Logging:")
        model: ruleChoices
        textRole: "text"
        currentIndex: ruleChoices.arrayIndex((rules) => rules.data == rule.logging)
        onCurrentIndexChanged: rule.logging = ruleChoices[currentIndex].data
    }

    Item {
        Layout.fillHeight: true
    }
    RowLayout {
        QQC2.Button {
            text: i18n("Accept")
            icon.name: "dialog-ok"
            enabled: (!incoming.checked && policyChoices[policy.currentIndex].data !== defaultOutgoingPolicyRule)
                  || (incoming.checked && policyChoices[policy.currentIndex].data !== defaultIncomingPolicyRule)
            onClicked: accept(rule)
        }
    }
}
