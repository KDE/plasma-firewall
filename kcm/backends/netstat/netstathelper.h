// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#ifndef NETSTATHELPER_H
#define NETSTATHELPER_H

#include <KAuth>
#include <QVariantMap>

#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(NetstatHelperDebug)

using namespace KAuth;
class NetstatHelper : public QObject
{
    Q_OBJECT
public:
    NetstatHelper();

public Q_SLOTS:
    ActionReply query(const QVariantMap &map);

private:
    QVariantList parseOutput(const QByteArray &netstatOutput);
    QVariantList parseNetstatOutput(const QByteArray &netstatOutput);
    QVariantList parseSSOutput(const QByteArray &ss);

    QString extractAndStrip(const QString &src, const int &index, const int &size);

    /* Netstat has been deprecated for more than 20 years,
     * some distros such as arch linux use 'ss' as default.
     */
    int mHasSS;

    /* Distros are not obliged to install this. let's query it before
     * assuming that this actually exists */
    int mHasNetstat;
};

#endif // NETSTATHELPER_H
