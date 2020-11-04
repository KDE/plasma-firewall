// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#ifndef NETSTATHELPER_H
#define NETSTATHELPER_H

#include <QVariantMap>
#include <QLoggingCategory>
#include <QProcess>

Q_DECLARE_LOGGING_CATEGORY(NetstatHelperDebug)

class QTimer;

class NetstatHelper : public QObject
{
    Q_OBJECT
public:
    NetstatHelper();
    QString errorString() const;
    bool hasError() const;

public Q_SLOTS:
    void query();
    void stopProcess();

private Q_SLOTS:
    // called by the finished signal on the process.
    void stepExecuteFinished(int exitCode, QProcess::ExitStatus exitStatus);

Q_SIGNALS:
    void queryFinished(const QVector<QStringList>& query);

private:
    QVector<QStringList> parseSSOutput(const QByteArray &ss);

    QString extractAndStrip(const QString &src, const int &index, const int &size);

    void resetPointers();

    QString m_errorString;
    bool m_hasError;
    QProcess *m_executableProcess;
    QTimer *m_processKillerTimer;
    bool m_hasTimeoutError;

};

#endif // NETSTATHELPER_H
