#include <QDebug>
#include <QCoreApplication>

#include "firewallclient.h"
#include "rulelistmodel.h"
#include "rule.h"

#include <KJob>

// Start
void testDisableClient(FirewallClient* client);
void testDisableClientResult(FirewallClient* client, KJob *job);

// Second Method.
void testEnableClient(FirewallClient* client);
void testEnableClientResult(FirewallClient* client, KJob *job);

// Third Method
void testCurrentRulesEmpty(FirewallClient* client);
void testCurrentRulesEmptyResult(FirewallClient* client);

// Fourth Method
void testAddRules(FirewallClient* client);
void testAddRulesResult(FirewallClient* client, KJob *job);

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
    testEnableClient(client);
}

void testEnableClient(FirewallClient* client) {
    // From here on, We will jump thru the usage via connects.
    KJob *enableJob = client->setEnabled(true);
    QObject::connect(enableJob, &KJob::result, [client, enableJob]{ testEnableClientResult(client, enableJob); });
    enableJob->start();
}

void testEnableClientResult(FirewallClient *client, KJob *job) {
    if (job->error() != KJob::NoError) {
        qDebug() << "Error disabling the client, aborting." << client->enabled();
        qDebug() << job->errorString();
        exit(1);
    }

    qDebug() << "Enable client, expected: True, got:" << client->enabled();
    testCurrentRulesEmpty(client);
}

void testCurrentRulesEmpty(FirewallClient* client)
{
    if (client->rulesModel()->rowCount() != 0) {
        qDebug() << "We need a clean firewall rules to do the testing, please backup your rules and try again.";
        exit(1);
    }

    qDebug() << "Number of current rules, Expected: 0, got:" << client->rulesModel()->rowCount();
    testCurrentRulesEmptyResult(client);
}

void testCurrentRulesEmptyResult(FirewallClient* client)
{
    testAddRules(client);
}


// Fourth Method
void testAddRules(FirewallClient* client) {
    qDebug() << "Known Protocols" << client->knownProtocols();
    qDebug() << "Known Interfaces" << client->knownInterfaces();

    QString interface = client->knownInterfaces()[0];

    auto *rule = new Rule(
        Types::Policy::POLICY_ALLOW, // Policy
        true,                        // Incomming?
        Types::Logging::LOGGING_ALL, // Logging
        0,                           // Protocol Id on knownProtocols
        "127.0.0.1",                 // Source Host
        "12",                        // Source Port
        "127.0.0.1",                 // Destination Port
        "21",                        // Destination Port
        interface,                   // Interface In
        interface,                   // Interface Out
        "source_app",                // Source App
        "destination_app",           // Destination App
        0,                           // Index (TODO: Remove This)
        false);                      // IPV6?

    KJob *job = client->addRule(rule);
    QObject::connect(job, &KJob::result, [client, job]{ testAddRulesResult(client, job); });
    // This job is started inside of the addRule
    // job->start();
}

void testAddRulesResult(FirewallClient* client, KJob *job)
{
    if (job->error() != KJob::NoError) {
        qDebug() << "Add rules failed" << job->errorString();
        exit(1);
    }

    qDebug() << "Add Rules succeeded, number of rules:" << client->rulesModel()->rowCount();
}

