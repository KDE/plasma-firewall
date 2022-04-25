// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2011 Craig Drummond <craig.p.drummond@gmail.com>
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>
/*
 * UFW KControl Module
 */

#pragma once

#include <kcm_firewall_core_export.h>

#include <QAbstractListModel>
#include <QVariantList>

struct LogData {
    QString sourceAddress;
    QString sourcePort;
    QString destinationAddress;
    QString destinationPort;
    QString protocol;
    QString interface;
    QString action;
    QString time;
    QString date;
};
Q_DECLARE_TYPEINFO(LogData, Q_MOVABLE_TYPE);

class KCM_FIREWALL_CORE_EXPORT LogListModel : public QAbstractListModel
{
    Q_OBJECT

    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)

public:
    explicit LogListModel(QObject *parent = nullptr);

    enum LogItemModelRoles {
        SourceAddressRole = Qt::UserRole + 1,
        SourcePortRole,
        DestinationAddressRole,
        DestinationPortRole,
        ProtocolRole,
        InterfaceRole,
        ActionRole,
        TimeRole,
        DateRole,
    };
    Q_ENUM(LogItemModelRoles)

    bool busy() const;
    void setBusy(bool busy);
    Q_SIGNAL void busyChanged();

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    virtual void addRawLogs(const QStringList &rawLogsList) = 0;

    void appendLogData(const QVector<LogData> newData);

Q_SIGNALS:
    void countChanged();

    void showErrorMessage(const QString &message);

protected:
    QHash<int, QByteArray> roleNames() const override;

private:
    QVector<LogData> m_logsData;
    bool m_busy = false;
};
