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
            out << 1 << SSH_AGENT_FAILURE;
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
    default:
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
    char ret = success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE;
    out << 1;
    out << ret;
}

