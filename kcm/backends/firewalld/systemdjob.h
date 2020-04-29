/*
 * Firewalld backend for plasma firewall
 *
 * Copyright 2020 Lucas Biaggi <lbjanuario@gmail.com>
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

#ifndef SYSTEMDJOB_H
#define SYSTEMDJOB_H

#include <KJob>
#include <types.h>

namespace SYSTEMD {
    enum actions {ERROR=-1, STOP, START };
}

class SystemdJob : public KJob {
    Q_OBJECT

public:
    SystemdJob(const SYSTEMD::actions &action);
    ~SystemdJob() {};
    void start() override;
    QString name();

private:
    void systemdAction(const SYSTEMD::actions value);
    SYSTEMD::actions m_action;

};

#endif
