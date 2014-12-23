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
