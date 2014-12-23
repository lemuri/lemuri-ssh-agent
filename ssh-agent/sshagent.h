/***************************************************************************
 *   Copyright (C) 2014 Daniel Nicoletti <dantti12@gmail.com>              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; see the file COPYING. If not, write to       *
 *   the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,  *
 *   Boston, MA 02110-1301, USA.                                           *
 ***************************************************************************/

#ifndef SSHAGENT_H
#define SSHAGENT_H

#include <QObject>

class QLocalSocket;
class SshAgent : public QObject
{
    Q_OBJECT
public:
    explicit SshAgent(QObject *parent = 0);
    ~SshAgent();

    bool listen(const QString &path);

private:
    void newConnection();
    void readyRead();

    void lockAgent(QLocalSocket *socket, QDataStream &in, bool lock);

    QByteArray m_lockedPassword;
    bool m_locked = false;
};

#endif // SSHAGENT_H
