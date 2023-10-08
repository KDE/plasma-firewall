// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

import QtQml 2.12
import QtQuick 2.12
import QtQuick.Layouts 1.3
import QtQuick.Controls 2.12 as QQC2
import QtQuick.Controls 1.4 as QQC1
import org.kde.kirigami 2.14 as Kirigami

import org.kde.kcmutils as KCMUtils
import org.kde.kitemmodels 1.0
import org.kcm.firewall 1.0

KCMUtils.ScrollViewKCM {
    id: root

    property QtObject model
    property var roles: []
    property alias emptyListText: emptyListLabel.text

    property QtObject currentJob: null

    property var blacklistRuleFactory
    property var blacklistRuleRoleNames: []
    property string blacklistRuleSuccessMessage

    property string defaultSortRole: ""

    property alias filterPlaceholderText: searchField.placeholderText
    property var filterRoleNames: []

    property var errorMessage: modelErrorMessage

    KSortFilterProxyModel {
        id: proxyModel
        sourceModel: root.model
        sortRole: tableView.sortIndicatorColumn > -1 ? roles[tableView.sortIndicatorColumn].role : ""
        sortOrder: tableView.sortIndicatorOrder

        function filterCb(source_row, source_parent) {
            const query = searchField.text.toLocaleLowerCase();
            const roleNames = filterRoleNames;

            const modelType = getModelType();
            const idx = sourceModel.index(source_row, 0, source_parent);

            for (var i = 0, length = roleNames.length; i < length; ++i) {
                const roleName = roleNames[i];
                const data = String(sourceModel.data(idx, modelType[roleName + "Role"]) || "").toLocaleLowerCase();

                if (data.includes(query)) {
                    return true;
                }
            }

            return false;
        }

        filterRowCallback: searchField.length > 0 && filterRoleNames.length > 0 ? filterCb : null
    }

    function getModelType() {
        // can this be done generically? :(
        if (root.model instanceof LogListModel) {
            return LogListModel;
        } else if (root.model instanceof ConnectionsModel) {
            return ConnectionsModel;
        }
        return null;
    }

    function blacklistRow(row) {
        // FIXME why does TableView does that? :(
        // Unfortunately it also casts to 0, so the resulting model index is deemed valid
        if (row === undefined) {
            return;
        }

        console.log("Accessing blacklist row", row);
        const idx = proxyModel.index(row, 0);
        const roles = blacklistRuleRoleNames;
        const modelType = getModelType();
        const args = roles.map((role) => {
            return proxyModel.data(idx, modelType[role + "Role"]);
        });

        if (args[0] === undefined) {
            console.log("Error, a model refresh happened when you tried to blacklist a connection.");
            return;
        }

        const rule = blacklistRuleFactory(...args);
        const job = kcm.client.addRule(rule);

        currentJob = job;
        ruleCreationErrorMessage.visible = false;
        console.log(...args);

        job.result.connect(function() {
            currentJob = null;

            if (job.error) {
                if (job.error !== 4) { // FIXME magic number
                    let indexError = job.errorString.indexOf("ERROR:");
                    let errorStrings = job.errorString.substring(indexError);

                    console.log(errorStrings);
                    ruleCreationErrorMessage.text = i18n("Error creating rule: %1", errorStrings);
                    ruleCreationErrorMessage.visible = true;
                }
                return;
            }

            if (blacklistRuleSuccessMessage) {
                kcm.showPassiveNotification(blacklistRuleSuccessMessage);
            }
        });
    }

    extraFooterTopPadding: false

    header: ColumnLayout {
        Kirigami.InlineMessage {
            id: modelErrorMessage
            Layout.fillWidth: true
            type: Kirigami.MessageType.Error
            showCloseButton: true

            Connections {
                target: root.model
                function onShowErrorMessage(message) {
                    modelErrorMessage.text = message;
                    modelErrorMessage.visible = true;
                }
            }
        }

        Kirigami.InlineMessage {
            id: ruleCreationErrorMessage
            type: Kirigami.MessageType.Error
            Layout.fillWidth: true
            showCloseButton: true
        }

        Kirigami.SearchField {
            id: searchField
            Layout.fillWidth: true
            onTextChanged: proxyModel.invalidateFilter();
            enabled: root.model.count > 0
            visible: root.filterRoleNames.length > 0
        }
    }

    view: Flickable {
        QQC1.TableView {
            id: tableView
            anchors.fill: parent
            activeFocusOnTab: true

            // ScrollViewKCM does its own frame
            frameVisible: false

            sortIndicatorVisible: sortIndicatorColumn > 0 // column -1 apparently means "do something stupid" rather than "no column"
            sortIndicatorColumn: root.roles.findIndex((column) => {
                return column.role === root.defaultSortRole;
            });

            // Would be nice to support multi-selection
            //selectionMode: QQC1.SelectionMode.ExtendedSelection

            // TODO let Delete key add blacklist rule?

            QQC2.BusyIndicator {
                anchors.centerIn: parent
                // Show busy spinner only on initial population and not while an error is shown
                running: root.model.count === 0 && root.model.busy && !modelErrorMessage.visible
            }

            Kirigami.PlaceholderMessage {
                id: emptyListLabel
                anchors.centerIn: parent
                width: parent.width - (Kirigami.Units.largeSpacing * 4)
                visible: root.model.count === 0 && !root.model.busy && !modelErrorMessage.visible
            }

            model: proxyModel

            Instantiator {
                id: columnInstantiator
                model: root.roles
                delegate: QQC1.TableViewColumn {
                    title: modelData.title
                    role: modelData.role
                    width: {
                        // Stretch last column to fill
                        if (index === columnInstantiator.count - 1) {
                            let rest = tableView.viewport.width;
                            for (let i = 0; i < tableView.columnCount - 1; ++i) {
                                rest -= tableView.getColumn(i).width;
                            }
                            return Math.max(modelData.width, rest);
                        }
                        return modelData.width;
                    }
                }
                onObjectAdded: tableView.addColumn(object);
            }
        }
    }

    footer: RowLayout {
        Item {
            Layout.fillWidth: true
        }

        InlineBusyIndicator {
            horizontalAlignment: Qt.AlignRight
            running: root.currentJob
        }

        QQC2.Button {
            text: i18n("Blacklist Connection")
            icon.name: "network-disconnect"
            // HACK TableView lets us select a fake zero index when view is empty...
            enabled: tableView.selection.count > 0 && model.count > 0 && !root.currentJob
            onClicked: blacklistRow(tableView.selection.forEach(blacklistRow))
        }
    }
}
