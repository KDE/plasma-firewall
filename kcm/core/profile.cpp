/*
 * UFW KControl Module
 *
 * Copyright 2011 Craig Drummond <craig.p.drummond@gmail.com>
 * Copyright 2018 Alexis Lopes Zubeta <contact@azubieta.net>
 * Copyright 2020 Tomaz Canabrava <tcanabrava@kde.org>
 *
 * ----
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "profile.h"
#include "types.h"

#include <QBuffer>
#include <QDebug>
#include <QFile>
#include <QIODevice>
#include <QStringList>
#include <QTextStream>
#include <QXmlStreamReader>

Profile::Profile(QByteArray &xml, bool isSys)
    : fields(0)
    , enabled(false)
    , ipv6Enabled(false)
    , logLevel(Types::LOG_OFF)
    , defaultIncomingPolicy(Types::POLICY_ALLOW)
    , defaultOutgoingPolicy(Types::POLICY_ALLOW)
    , isSystem(isSys)
{
    QBuffer buffer;
    buffer.setBuffer(&xml);
    load(&buffer);
}

Profile::Profile(QFile &file, bool isSys)
    : fields(0)
    , enabled(false)
    , ipv6Enabled(false)
    , logLevel(Types::LOG_OFF)
    , defaultIncomingPolicy(Types::POLICY_ALLOW)
    , defaultOutgoingPolicy(Types::POLICY_ALLOW)
    , fileName(file.fileName())
    , isSystem(isSys)
{
    load(&file);
}

Profile::Profile(const QVector<Rule> &rules, const QVariantMap &args, bool isSys)
    : isSystem(isSys)
{
    setRules(rules);
    setArgs(args);
}

void Profile::setRules(const QVector<Rule> &newrules)
{
    rules = newrules;
}

void Profile::setArgs(const QVariantMap &args)
{
    const QString new_defaultIncomingPolicy = args.value(QStringLiteral("defaultIncomingPolicy")).toString();
    const QString new_defaultOutgoingPolicy = args.value(QStringLiteral("defaultIncomingPolicy")).toString();
    const QString new_loglevel = args.value(QStringLiteral("logLevel")).toString();
    const QStringList new_modules = args.value(QStringLiteral("modules")).toStringList();

    defaultIncomingPolicy = new_defaultIncomingPolicy.isEmpty() ? Types::POLICY_ALLOW : Types::toPolicy(new_defaultIncomingPolicy);
    defaultOutgoingPolicy = new_defaultOutgoingPolicy.isEmpty() ? Types::POLICY_ALLOW : Types::toPolicy(new_defaultOutgoingPolicy);
    logLevel = new_loglevel.isEmpty() ? Types::LOG_OFF : Types::toLogLevel(new_loglevel);
    enabled = args.value("status").toBool();
    ipv6Enabled = args.value("ipv6Enabled").toBool();

    if (!new_modules.isEmpty()) {
        modules = QSet<QString>(std::begin(new_modules), std::end(new_modules));
    }
}

void Profile::setDefaultIncomingPolicy(const QString &policy)
{
    defaultIncomingPolicy = Types::toPolicy(policy);
}

void Profile::setDefaultOutgoingPolicy(const QString &policy)
{
    defaultOutgoingPolicy = Types::toPolicy(policy);
}

QString Profile::toXml() const
{
    QString str;
    QTextStream stream(&str);

    stream << "<ufw full=\"true\" >" << endl << ' ' << defaultsXml() << endl << " <rules>" << endl;

    for (const auto &rule : rules) {
        stream << "  " << rule.toXml();
    }

    stream << " </rules>" << endl << ' ' << modulesXml() << endl << "</ufw>" << endl;

    return str;
}

QString Profile::defaultsXml() const
{
    static const auto defaultString = QStringLiteral(R"(<defaults ipv6="%1" loglevel="%2" incoming="%3" outgoing="%4"/>)");

    return defaultString
        .arg(ipv6Enabled ? "yes" : "no")
        .arg(Types::toString(logLevel))
        .arg(Types::toString(defaultIncomingPolicy))
        .arg(Types::toString(defaultOutgoingPolicy));
}

QString Profile::modulesXml() const
{
    return QString("<modules enabled=\"") + QStringList(modules.toList()).join(" ") + QString("\" />");
}

void Profile::load(QIODevice *device)
{
    device->open(QIODevice::ReadOnly);
    QXmlStreamReader reader(device);

    bool isFullProfile = false;
    while (!reader.atEnd()) {
        auto token = reader.readNext();
        if (token == QXmlStreamReader::Invalid) {
            break;
        }
        if (token != QXmlStreamReader::StartElement) {
            continue;
        }
        if (reader.name() == QStringLiteral("ufw")) {
            isFullProfile = reader.attributes().value("full") == QStringLiteral("true");
            continue;
        }
        if (reader.name() == QStringLiteral("status")) {
            enabled = reader.attributes().value("enabled") == QStringLiteral("true");
            fields |= FIELD_STATUS;
        }
        if (reader.name() == QStringLiteral("rules")) {
            fields |= FIELD_RULES;
            continue;
        }
        if (reader.name() == "rule") {
            static QString ANY_ADDR = "0.0.0.0/0";
            static QString ANY_ADDR_V6 = "::/0";
            static QString ANY_PORT = "any";

            const auto attr = reader.attributes();

            // Handle Enums.
            const auto action = Types::toPolicy(attr.value(QLatin1String("action")).toString());
            const auto protocol = Types::toProtocol(attr.value(QLatin1String("protocol")).toString());
            const auto logType = Types::toLogging(attr.value(QLatin1String("logtype")).toString());

            // Handle values that have weird defaults.
            const auto anyAddrs = QList<QString>({ANY_ADDR, ANY_ADDR_V6});
            const auto dst = attr.value("dst").toString();
            const auto src = attr.value("src").toString();
            const auto sport = attr.value("sport").toString();
            const auto dport = attr.value("dport").toString();

            const QString destAddress = anyAddrs.contains(dst) ? QString() : dst;
            const QString sourceAddress = anyAddrs.contains(src) ? QString() : src;
            const QString sourcePort = sport == ANY_PORT ? QString() : sport;
            const QString destPort = dport == ANY_PORT ? QString() : dport;

            rules.append(Rule(action,
                              attr.value("direction") == QStringLiteral("in"),
                              logType,
                              protocol,
                              sourceAddress,
                              sourcePort,
                              destAddress,
                              destPort,
                              attr.value("interface_in").toString(),
                              attr.value("interface_out").toString(),
                              attr.value("sapp").toString(),
                              attr.value("dapp").toString(),
                              attr.value("position").toInt(),
                              attr.value("v6") == QStringLiteral("True")));
        }
        if (reader.name() == "defaults") {
            fields |= FIELD_DEFAULTS;

            const auto attr = reader.attributes();

            logLevel = Types::toLogLevel(attr.value(QLatin1String("loglevel")).toString());

            defaultIncomingPolicy = Types::toPolicy(attr.value(QLatin1String("incoming")).toString());
            defaultOutgoingPolicy = Types::toPolicy(attr.value(QLatin1String("outgoing")).toString());

            ipv6Enabled = (attr.value("ipv6") == QLatin1String("yes"));
        }
        if (reader.name() == "modules") {
            fields |= FIELD_MODULES;
            const auto attr = reader.attributes();
            const auto moduleList = attr.value("enabled").toString().split(" ", Qt::SkipEmptyParts);
            modules = QSet<QString>(std::begin(moduleList), std::end(moduleList));
        }
    }
    if (isFullProfile && (!(fields & FIELD_RULES) || !(fields & FIELD_DEFAULTS) || !(fields & FIELD_MODULES))) {
        fields = 0;
    }
}

void Profile::setEnabled(const bool &value) {
        enabled = value;
}
