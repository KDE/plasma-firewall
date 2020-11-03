// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#ifndef NETSTATHELPER_H
#define NETSTATHELPER_H

#include <QVariantMap>
#include <QTimer>
#include <QElapsedTimer>
#include <QLoggingCategory>
#include <QThread>

Q_DECLARE_LOGGING_CATEGORY(NetstatHelperDebug)

class NetstatHelper : public QThread
{
    Q_OBJECT
public:
    NetstatHelper();

    void run() override;
public Q_SLOTS:
    QString errorString() const;
    bool hasError() const;

    /*
    if the query takes too long, this timeout happens,
    closing the old process, and reopening. 
    */
    void timeout();

signals:
    void queryFinished(const QVector<QStringList>& values);

private:
    QVector<QStringList> parseSSOutput(const QByteArray &ss);

    QString extractAndStrip(const QString &src, const int &index, const int &size);
    QString m_errorString;
    bool m_hasError;
    QTimer m_timer;
    QElapsedTimer m_elapsedTimer;
};

#endif // NETSTATHELPER_H
