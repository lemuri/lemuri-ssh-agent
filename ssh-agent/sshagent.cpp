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

// THIS Code is based on the ssh-agent.c code which has the following authors
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "sshagent.h"

#include <QLocalServer>
#include <QLocalSocket>
#include <QFile>
#include <QProcess>
#include <QDebug>

/* Messages for the authentication agent connection. */
#define SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#define SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#define SSH_AGENTC_RSA_CHALLENGE		3
#define SSH_AGENT_RSA_RESPONSE			4
#define SSH_AGENT_FAILURE			5
#define SSH_AGENT_SUCCESS			6
#define SSH_AGENTC_ADD_RSA_IDENTITY		7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY		8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#define SSH2_AGENTC_REQUEST_IDENTITIES		11
#define SSH2_AGENT_IDENTITIES_ANSWER		12
#define SSH2_AGENTC_SIGN_REQUEST		13
#define SSH2_AGENT_SIGN_RESPONSE		14
#define SSH2_AGENTC_ADD_IDENTITY		17
#define SSH2_AGENTC_REMOVE_IDENTITY		18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#define SSH_AGENTC_ADD_SMARTCARD_KEY		20
#define SSH_AGENTC_REMOVE_SMARTCARD_KEY		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED 26

SshAgent::SshAgent(QObject *parent) : QObject(parent)
{

}

SshAgent::~SshAgent()
{

}

bool SshAgent::listen(const QString &path)
{
    QLocalServer *server = new QLocalServer(this);
    if (server->listen(path) ||
            (server->serverError() == QAbstractSocket::AddressInUseError &&
             QFile::remove(path) &&
             server->listen(path))) {

        connect(server, &QLocalServer::newConnection,
                this, &SshAgent::newConnection);

        return true;
    }

    qDebug() << server->errorString() << server->serverError();
    delete server;
    return false;
}

void SshAgent::newConnection()
{
    qDebug() << Q_FUNC_INFO;
    QLocalServer *server = qobject_cast<QLocalServer *>(sender());
    QLocalSocket *socket = server->nextPendingConnection();
    qDebug() << Q_FUNC_INFO << socket;
    if (socket) {
        connect(socket, &QLocalSocket::readyRead,
                this, &SshAgent::readyRead);
    }
}

void SshAgent::readyRead()
{
    QLocalSocket *socket = qobject_cast<QLocalSocket *>(sender());
    qDebug() << Q_FUNC_INFO << "bytesAvailable" << socket->bytesAvailable();

    // Read current data and store on the socket object
    QByteArray request = socket->property("request").toByteArray();
    request.append(socket->readAll());
    socket->setProperty("request", request);

    qDebug() << Q_FUNC_INFO << request.size();

    if (request.size() < 5) {
        // Incomplete message
        return;
    }

    QDataStream in(request);

    quint32 msg_len;
    in >> msg_len;
    if (msg_len > 256 * 1024) {
        socket->close();
        socket->deleteLater();
        return;
    }

    if (in.device()->bytesAvailable() < msg_len) {
        // not enough data
        return;
    }

    uchar type;
    in >> type;
    qDebug() << Q_FUNC_INFO << "type" << type;
    if (m_locked && type != SSH_AGENTC_UNLOCK) {
        switch (type) {
        case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
        case SSH2_AGENTC_REQUEST_IDENTITIES:
            /* send empty lists */
//            no_identities(e, type);
            break;
        default:
            /* send a fail message for all other request types */
            QDataStream out(socket);
            out << 1 << quint8(SSH_AGENT_FAILURE);
        }
        return;
    }

    switch (type) {
    case SSH_AGENTC_LOCK:
        lockAgent(socket, in, true);
        break;
    case SSH_AGENTC_UNLOCK:
        lockAgent(socket, in, false);
        break;
#ifdef WITH_SSH1
    /* ssh1 */
    case SSH_AGENTC_RSA_CHALLENGE:
        process_authentication_challenge1(e);
        break;
    case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
        process_request_identities(e, 1);
        break;
    case SSH_AGENTC_ADD_RSA_IDENTITY:
    case SSH_AGENTC_ADD_RSA_ID_CONSTRAINED:
        process_add_identity(e, 1);
        break;
    case SSH_AGENTC_REMOVE_RSA_IDENTITY:
        process_remove_identity(e, 1);
        break;
    case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
        process_remove_all_identities(e, 1);
        break;
#endif
    /* ssh2 */
    case SSH2_AGENTC_SIGN_REQUEST:
//        process_sign_request2(e);
        break;
    case SSH2_AGENTC_REQUEST_IDENTITIES:
//        process_request_identities(e, 2);
        break;
    case SSH2_AGENTC_ADD_IDENTITY:
    case SSH2_AGENTC_ADD_ID_CONSTRAINED:
//        process_add_identity(e, 2);
        break;
    case SSH2_AGENTC_REMOVE_IDENTITY:
//        process_remove_identity(e, 2);
        break;
    case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
//        process_remove_all_identities(e, 2);
        break;
#ifdef ENABLE_PKCS11
    case SSH_AGENTC_ADD_SMARTCARD_KEY:
    case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
        process_add_smartcard_key(e);
        break;
    case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
        process_remove_smartcard_key(e);
        break;
#endif /* ENABLE_PKCS11 */
    default:
        /* Unknown message.  Respond with failure. */
        qWarning("Unknown message %d", type);
        QDataStream out(socket);
        out << 1 << quint8(SSH_AGENT_FAILURE);
        break;
    }

//    QByteArray buffer = socket->read(sizeof(msg_len));
//    msg_len = buffer.toUInt();
    qDebug() << "msg_len" << msg_len;

//    char type = buffer.at(0);
//    qDebug() << "type" << type;

    if (socket->bytesAvailable() == 5) {
        QProcess::execute("kdialog",
        {"--password", tr("Please enter the password for the key"),
         "--title", "SSH Private Key"});
    }
}

void SshAgent::lockAgent(QLocalSocket *socket, QDataStream &in, bool lock)
{
    QByteArray password;
    in >> password;
    qDebug() << "lockAgent" << lock;

    bool success = false;
    if (m_locked && !lock && password == m_lockedPassword) {
        m_locked = false;
        m_lockedPassword = QByteArray();
        success = true;
    } else if (!m_locked && lock) {
        m_locked = true;
        m_lockedPassword = password;
        success = true;
    }

    qDebug() << "lockAgent success" << success << m_locked;
    QDataStream out(socket);
    out << 1 << quint8(success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

void SshAgent::addIdentity(QLocalSocket *socket, QDataStream &in, int version)
{
    switch (version) {
#ifdef WITH_SSH1
    case 1:

        break;
#endif /* WITH_SSH1 */
    case 2:

    }

    QDataStream out(socket);
    out << 1 << quint8(SSH_AGENT_FAILURE);
}

