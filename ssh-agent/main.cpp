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

#include <QCoreApplication>
#include <QLocale>
#include <QTranslator>
#include <QLibraryInfo>
#include <QProcess>
#include <QDebug>

#include "config.h"

#include "sshagent.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    QCoreApplication::setOrganizationName("lemuri");
    QCoreApplication::setOrganizationDomain("lemuri.org");
    QCoreApplication::setApplicationName("lemuri-ssh-manager");
    QCoreApplication::setApplicationVersion(APP_VERSION);

    QTranslator qtTranslator;
    qtTranslator.load("qt_" + QLocale::system().name(),
                      QLibraryInfo::location(QLibraryInfo::TranslationsPath));
    QCoreApplication::installTranslator(&qtTranslator);

    QProcess::execute("kill", {"-9", qgetenv("SSH_AGENT_PID")});

    SshAgent *agent = new SshAgent;
    if (!agent->listen(qgetenv("SSH_AUTH_SOCK"))) {
        exit(1);
    }

    return app.exec();
}
