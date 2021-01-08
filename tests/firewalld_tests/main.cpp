#include <QDebug>
#include <QCoreApplication>

#include "firewallclient.h"
#include <KJob>

// Start
void testDisableClient(FirewallClient* client);
void testDisableClientResult(FirewallClient* client, KJob *job);

// Second Method.
void testEnableClient(FirewallClient* client);
void testEnableClientResult(FirewallClient* client, KJob *job);

// Third Method

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    qDebug() << "FirewallD test called";

    auto *client = new FirewallClient();
    client->setBackend({"firewalld"});

    qDebug() << "Backend Loaded" << client->backend() << "expected firewalld";

    // Initial backend state.
    qDebug() << "Client Enabled?" << client->enabled();

    // Start trying to disable, the order of calls is the same as the definition order.
    // Please don't change as this is really annoying to test.
    testDisableClient(client);

    return app.exec();
}

void testDisableClient(FirewallClient* client) {
    // From here on, We will jump thru the usage via connects.
    KJob *enableJob = client->setEnabled(false);
    QObject::connect(enableJob, &KJob::result, [client, enableJob]{ testDisableClientResult(client, enableJob); });
    enableJob->start();
}

void testDisableClientResult(FirewallClient *client, KJob *job) {
    if (job->error() != KJob::NoError) {
        qDebug() << "Error disabling the client, aborting." << client->enabled();
        qDebug() << job->errorString();
        exit(1);
    }

    qDebug() << "Disable client, expected: False, got:" << client->enabled();
}
