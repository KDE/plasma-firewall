// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

import QtQuick 2.12
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.1

import QtQuick.Controls 2.12 as QQC2
import org.kde.kirigami 2.4 as Kirigami

import org.kcm.firewall 1.0 as Firewall

FocusScope {
    id: ruleEdit

    signal accepted

    property bool busy: false

    property Firewall.FirewallClient client: null

    property var defaultOutgoingPolicyRule: null
    property var defaultIncomingPolicyRule: null

    property var rule: Firewall.Rule {
        policy: "deny"
        incoming: true
        logging: "none"
        protocol: 0
    }

    property var ruleChoices : [
        {text: i18n("None"), data: "none"},
        {text: i18n("New Connections"), data: "log"},
        {text: i18n("All Packets"), data: "log-all"}
    ]
    property bool newRule: false

    enabled: !busy

    implicitWidth: formLayout.implicitWidth
    implicitHeight: formLayout.implicitHeight

    Kirigami.FormLayout {
        id: formLayout
        width: parent.width

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            type: Kirigami.MessageType.Information
            text: rule.incoming ? i18n("The default incoming policy is already '%1'.", policy.currentText)
                                : i18n("The default outgoing policy is already '%1'.", policy.currentText)
            visible: rule.policy === (incoming.checked ? defaultIncomingPolicyRule : defaultOutgoingPolicyRule)
        }

        QQC2.ComboBox {
            id: policy
            Kirigami.FormData.label: i18n("Policy:")
            model: policyChoices
            textRole: "text"
            currentIndex: rule.policy == "" ? 0 : policyChoices.findIndex((policy) => policy.data == rule.policy)
            onActivated: rule.policy = policyChoices[index].data
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
            Kirigami.FormData.label: i18n("IP Version:")

            QQC2.RadioButton {
                text: i18n("IPv4")
                checked: !rule.ipv6
                onClicked: rule.ipv6 = false;
            }
            QQC2.RadioButton {
                text: i18n("IPv6")
                checked: rule.ipv6
                onClicked: rule.ipv6 = true
            }
        }

        RowLayout {
            Kirigami.FormData.label: i18n("Source:")

            IpTextField {
                id: sourceAddress
                ipv6: rule.ipv6
                focus: true // default focus object
                text: rule.sourceAddress
                Layout.preferredWidth: policy.width * 0.6
                // NOTE onEditingFinished doesn't fire with non-acceptable / empty input
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

            IpTextField {
                id: destinationAddress
                ipv6: rule.ipv6
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
            id: protocolCb

            Kirigami.FormData.label: i18n("Protocol:")
            model: ruleEdit.client.knownProtocols()
            currentIndex: rule.protocol
            onActivated: rule.protocol = index
        }
        QQC2.ComboBox {
            id: interfaceCb

            Kirigami.FormData.label: i18n("Interface:")
            model: ruleEdit.client.knownInterfaces()
            currentIndex: rule.interface
            onActivated: rule.interface = index
        }

        QQC2.ComboBox {
            Kirigami.FormData.label: i18n("Logging:")
            model: ruleChoices
            textRole: "text"
            currentIndex: rule.logging == "" ? 0 : ruleChoices.findIndex((rules) => rules.data == rule.logging)
            onActivated: rule.logging = ruleChoices[index].data
        }

        Item {
            Layout.fillHeight: true
        }
        RowLayout {
            QQC2.Button {
                text: ruleEdit.newRule ? i18n("Create") : i18n("Save")
                icon.name: ruleEdit.newRule ? "document-new" : "document-save"
                enabled: (!sourceAddress.length || sourceAddress.acceptableInput) && (!destinationAddress.length || destinationAddress.acceptableInput) && !(sourceAddress.text == destinationAddress.text && sourcePort.text == destinationPort.text)
                onClicked: ruleEdit.accepted()
            }

            // Would be nice to not have this one "disabled"
            InlineBusyIndicator {
                running: ruleEdit.busy
            }
        }
    }
}
