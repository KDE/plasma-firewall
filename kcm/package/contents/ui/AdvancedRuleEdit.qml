import QtQuick 2.12
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.1

import QtQuick.Controls 2.12 as QQC2
import org.kde.kirigami 2.4 as Kirigami

import org.kcm.firewall 1.0 as Firewall

Kirigami.FormLayout {
    property var rule: null
    property alias sourceAddress: sourceAddress
    property alias destinationAddress: destinationAddress
    property alias destinationPort: destinationPort
    property alias sourcePort: sourcePort
    property alias policy: policy
    property alias incoming: incoming

    QQC2.ComboBox {
        id: policy
        Kirigami.FormData.label: i18n("Policy:")
        model: policyChoices
        textRole: "text"
        currentIndex: rule == null ? 0 : rule.policy == "" ? 0 : policyChoices.findIndex((policy) => policy.data == rule.policy)
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
}
