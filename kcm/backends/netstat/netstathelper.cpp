// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
// SPDX-FileCopyrightText: 2018 Alexis Lopes Zubeta <contact@azubieta.net>
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#include "netstathelper.h"

#include <KLocalizedString>

#include <QDebug>
#include <QProcess>
#include <QStandardPaths>
#include <QStringList>

Q_LOGGING_CATEGORY(NetstatHelperDebug, "netstat.helper")

NetstatHelper::NetstatHelper() : m_hasError(false)
{
}

QVector<QStringList> NetstatHelper::query()
{
    m_hasError = false;
    QProcess netstat;
    /* parameters passed to ss
     *  -r, --resolve       resolve host names
     *  -a, --all           display all sockets
     *  -p, --processes     show process using socket
     *  -u, --udp           display only UDP sockets
     *  -t, --tcp           display only TCP sockets
     */
    QStringList netstatArgs({"-tuapr"});
    QString executable = QStringLiteral("ss");

    netstat.start(executable, netstatArgs, QIODevice::ReadOnly);
    if (netstat.waitForStarted()) {
        netstat.waitForFinished();
    }
    int exitCode = netstat.exitCode();

    QVector<QStringList> result;
    if (0 != exitCode) {
        m_hasError = true;
        m_errorString = netstat.readAllStandardError();
    } else {
        result = parseSSOutput(netstat.readAllStandardOutput());
    }

    return result;
}

bool NetstatHelper::hasError() const
{
    return m_hasError;
}

QString NetstatHelper::errorString() const
{
    return m_errorString;
}

QVector<QStringList> NetstatHelper::parseSSOutput(const QByteArray &netstatOutput)
{
    QString rawOutput = netstatOutput;
    QStringList outputLines = rawOutput.split("\n");

    QVector<QStringList> connections;

    // discard lines.
    while (outputLines.size()) {
        if (outputLines.first().indexOf("Recv-Q")) {
            outputLines.removeFirst();
            break;
        }
        outputLines.removeFirst();
    }

    // can't easily parse because of the spaces in Local and Peer AddressPort.
    QStringList headerLines = {
        QStringLiteral("Netid"),
        QStringLiteral("State"),
        QStringLiteral("Recv-Q"),
        QStringLiteral("Send-Q"),
        QStringLiteral("Local Address:Port"),
        QStringLiteral("Peer Address:Port"),
        QStringLiteral("Process"),
    };

    // Extract Information
    for (auto line : outputLines) {
        QStringList values = line.split(QLatin1Char(' '), QString::SkipEmptyParts);
        if (values.isEmpty()) {
            continue;
        }

        // Some lines lack one or two values.
        while (values.size() < headerLines.size()) {
            values.append(QString());
        }

        QString appName;
        QString pid;
        if (values[6].size()) {
            values[6].remove(0, QStringLiteral("users:((").size());
            values[6].chop(QStringLiteral("))").size());

            QStringList substrings = values[6].split(',');
            appName = substrings[0].remove("\"");
            pid = substrings[1].split('=')[1];
        }

        /* Insertion order needs to match the Model Columns:
            ProtocolRole = Qt::UserRole + 1,
            LocalAddressRole,
            ForeignAddressRole,
            StatusRole,
            PidRole,
            ProgramRole
        */
        QStringList connection {
            values[0], // NetId
            values[4], // Local Address
            values[5], // Peer Address,
            values[1], // State
            pid,
            appName,
        };

        connections.append(connection);
    }

    return connections;
}

QString NetstatHelper::extractAndStrip(const QString &src, const int &index, const int &size)
{
    QString str = src.mid(index, size);
    str.replace(" ", "");
    return str;
}
