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
    property alias simple: simpleRuleEdit

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
            currentIndex: rule.policy === "" ? 0 : policyChoices.findIndex((policy) => policy.data === rule.policy)
            onActivated: rule.policy = policyChoices[index].data
        }

        SimpleRuleEdit {
            id: simpleRuleEdit
            visible: !advancedRules.checked
        }

        CheckBox {
            id: advancedRules
            text:"Advanced"
            onClicked: rule.simplified = !rule.simplified
            checked: rule.simplified ? false : true // show advanced mode directly if isn't simple !
        }

        AdvancedRuleEdit {
            id: advancedRuleEdit
            rule: ruleEdit.rule
            visible: advancedRules.checked
        }

        Item {
            Layout.fillHeight: true
        }
        RowLayout {
            QQC2.Button {
                text: ruleEdit.newRule ? i18n("Create") : i18n("Save")
                icon.name: ruleEdit.newRule ? "document-new" : "document-save"
                enabled: (!sourceAddress.length || sourceAddress.acceptableInput) && (!destinationAddress.length || destinationAddress.acceptableInput) && !(sourceAddress.text == destinationAddress.text && sourcePort.text == destinationPort.text)
                onClicked: {
                    // rule.setSourceApplication(simple.service[simple.index]);
                    rule.sourceApplication = simple.service[simple.index]
                    ruleEdit.accepted()
                }

            }

            // Would be nice to not have this one "disabled"
            InlineBusyIndicator {
                running: ruleEdit.busy
            }
        }

    }
}
