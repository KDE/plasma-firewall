// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#ifndef NETSTATHELPER_H
#define NETSTATHELPER_H

#include <QVariantMap>

#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(NetstatHelperDebug)

class NetstatHelper : public QObject
{
    Q_OBJECT
public:
    NetstatHelper();

public Q_SLOTS:
    QVector<QStringList> query();
    QString errorString() const;
    bool hasError() const;

private:
    QVector<QStringList> parseSSOutput(const QByteArray &ss);

    QString extractAndStrip(const QString &src, const int &index, const int &size);
    QString m_errorString;
    bool m_hasError;
};

#endif // NETSTATHELPER_H
