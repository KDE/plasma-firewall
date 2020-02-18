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
        Kirigami.FormData.label: "Policy:"
        model: policyChoices
        textRole: "text"
        currentIndex: getCurrentIndex(rule.policy, policyChoices)
        onCurrentIndexChanged: rule.policy = policyChoices[currentIndex].data
    }

    RowLayout {
        Kirigami.FormData.label: "Direction:"
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
        Kirigami.FormData.label: "Source:"

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
        Kirigami.FormData.label: "Destination:"

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
        Kirigami.FormData.label: "Protocol:"

        id: protocolCb

        model: firewallClient.getKnownProtocols()

        currentIndex: rule.protocol
        onCurrentIndexChanged: rule.protocol = currentIndex
    }
    QQC2.ComboBox {
        Kirigami.FormData.label: "Interface:"

        id: interfaceCb

        model: firewallClient.getKnownInterfaces()

        currentIndex: rule.interface
        onCurrentIndexChanged: rule.interface = currentIndex

    }

    QQC2.ComboBox {
        Kirigami.FormData.label: "Logging:"
        model: ruleChoices
        textRole: "text"
        currentIndex: getCurrentIndex(rule.logging, ruleChoices)
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
