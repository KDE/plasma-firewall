// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2020 Lucas Biaggi <lbjanuario@gmail.com>
/*
 * Firewalld backend for plasma firewall
 */

#ifndef SYSTEMDJOB_H
#define SYSTEMDJOB_H

#include <KJob>
#include <types.h>

#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(SystemDJobDebug)

namespace SYSTEMD
{
enum actions { ERROR = -1, STOP, START };
}

class SystemdJob : public KJob
{
    Q_OBJECT

public:
    SystemdJob(const SYSTEMD::actions &action);
    ~SystemdJob();
    void start() override;
    QString name();

private:
    void systemdAction(const SYSTEMD::actions value);
    SYSTEMD::actions m_action;
};

#endif
