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
#include "dbustypes.h"

const QDBusArgument &operator>>(const QDBusArgument &argument, firewalld_reply &mystruct)
{
    argument.beginStructure();
    argument >> mystruct.ipv >> mystruct.table >> mystruct.chain >> mystruct.priority >> mystruct.rules;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator<<(QDBusArgument &argument, const firewalld_reply &mystruct)
{
    argument.beginStructure();
    argument << mystruct.ipv << mystruct.table << mystruct.chain << mystruct.priority << mystruct.rules;
    argument.endStructure();
    return argument;
}
