/*
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
 * Copyright 2020 Tomaz Canabrava <tcanabrava@kde.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License or (at your option) version 3 or any later version
 * accepted by the membership of KDE e.V. (or its successor approved
 * by the membership of KDE e.V.), which shall act as a proxy
 * defined in Section 14 of version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "netstathelper.h"

#include <QDebug>
#include <QProcess>
#include <QStandardPaths>
#include <QStringList>

NetstatHelper::NetstatHelper()
{
    mHasSS = !QStandardPaths::findExecutable("ss").isEmpty();

    if (!mHasSS) { // could not execute file
        qWarning() << "could not find iproute2 or net-tools packages installed.";
    }
}

KAuth::ActionReply NetstatHelper::query(const QVariantMap &map)
{
    Q_UNUSED(map);
    KAuth::ActionReply reply;

    QProcess netstat;
    /* parameters passed to ss
     *  -r, --resolve       resolve host names
     *  -a, --all           display all sockets
     *  -p, --processes     show process using socket
     *  -u, --udp           display only UDP sockets
     *  -t, --tcp           display only TCP sockets
     */
    QStringList netstatArgs({"-tuapr"});
    QString executable = mHasSS ? QStringLiteral("ss") : QString();

    if (executable.isEmpty()) {
        qWarning() << "No iproute or net-tools installed, can't run.";
        KAuth::ActionReply::HelperErrorReply(-2);
        return {};
    }

    qDebug() << "run" << executable << netstatArgs;

    netstat.start(executable, netstatArgs, QIODevice::ReadOnly);
    if (netstat.waitForStarted()) {
        netstat.waitForFinished();
    }
    int exitCode(netstat.exitCode());

    if (0 != exitCode) {
        reply = KAuth::ActionReply::HelperErrorReply(exitCode);
        reply.addData("response", netstat.readAllStandardError());
    } else {
        QVariantList connections = parseOutput(netstat.readAllStandardOutput());
        reply.addData("connections", connections);
    }

    return reply;
}

QVariantList NetstatHelper::parseOutput(const QByteArray &netstatOutput)
{
    if (mHasSS) {
        return parseSSOutput(netstatOutput);
    }
    return {};
}

QVariantList NetstatHelper::parseSSOutput(const QByteArray &netstatOutput)
{
    QString rawOutput = netstatOutput;
    QStringList outputLines = rawOutput.split("\n");

    QVariantList connections;

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
        QVariantList connection {
            values[0], // NetId
            values[4], // Local Address
            values[5], // Peer Address,
            values[1], // State
            pid,
            appName,
        };

        connections.append((QVariant)connection);
    }

    return connections;
}

QVariantList NetstatHelper::parseNetstatOutput(const QByteArray &netstatOutput)
{
    QString rawOutput = netstatOutput;
    QStringList outputLines = rawOutput.split("\n");

    QVariantList connections;

    int lineIdx = 0;
    int protIndex = 0, protSize = 0, localAddressIndex, localAddressSize, foreingAddressIndex, foreingAddressSize, stateIndex, stateSize, processIndex, processSize;

    for (auto line : outputLines) {
        lineIdx++;
        if (line.isEmpty()) {
            continue;
        }

        if (lineIdx == 1) {
            continue;
        }

        if (lineIdx == 2) {
            protIndex = 0;
            protSize = line.indexOf("Recv-Q");

            localAddressIndex = line.indexOf("Local Address");
            localAddressSize = line.indexOf("Foreign Address") - localAddressIndex;

            foreingAddressIndex = line.indexOf("Foreign Address");
            foreingAddressSize = line.indexOf("State") - foreingAddressIndex;

            stateIndex = line.indexOf("State");
            stateSize = line.indexOf("PID/Program name") - stateIndex;

            processIndex = line.indexOf("PID/Program name");
            processSize = line.size() - processSize;

            continue;
        }

        QVariantList connection(
            {extractAndStrip(line, protIndex, protSize), extractAndStrip(line, localAddressIndex, localAddressSize), extractAndStrip(line, foreingAddressIndex, foreingAddressSize), extractAndStrip(line, stateIndex, stateSize)});

        QString pidAndProcess = extractAndStrip(line, processIndex, processSize);

        int slashIndex = pidAndProcess.indexOf("/");
        if (slashIndex != -1) {
            QString pidStr = pidAndProcess.left(slashIndex);
            QString program = pidAndProcess.right(pidAndProcess.size() - slashIndex - 1);
            program = program.section(":", 0, 0);

            connection << pidStr.toInt();
            connection << program;
        }

        connections.append((QVariant)connection);
    }

    return connections;
}

QString NetstatHelper::extractAndStrip(const QString &src, const int &index, const int &size)
{
    QString str = src.mid(index, size);
    str.replace(" ", "");
    return str;
}

KAUTH_HELPER_MAIN("org.kde.netstat", NetstatHelper)
