#include "conectionsmodel.h"

#include <QDebug>

#include "netstatclient.h"

ConnectionsModel::ConnectionsModel(QObject *parent)
    : QAbstractListModel(parent), m_queryRunning(false)
    , m_queryAction(KAuth::Action(QStringLiteral("org.kde.netstat.query")))
{
    m_queryAction.setHelperId("org.kde.netstat");

    connect(&timer, &QTimer::timeout, this, &ConnectionsModel::refreshConnections);
    timer.setInterval(30000);
    timer.start();


    QTimer::singleShot(200, this, &ConnectionsModel::refreshConnections);
}

int ConnectionsModel::rowCount(const QModelIndex &parent) const
{
    // For list models only the root node (an invalid parent) should return the list's size. For all
    // other (valid) parents, rowCount() should return 0 so that it does not become a tree model.
    if (parent.isValid())
        return 0;

    return m_connectionsData.size();
}

QVariant ConnectionsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return {};

    if (index.row() < 0 || index.row() >= m_connectionsData.size())
        return {};

    QVariantList connection = m_connectionsData.at(index.row()).toList();

    int value_index = role - ProtocolRole;
    if (value_index < 0 || value_index >= connection.size())
        return {};


    return connection.at(value_index);
}

QVariant ConnectionsModel::data2(int row, const QByteArray &roleName) const
{
    const auto keys = roleNames().keys(roleName);
    if (keys.empty()) {
        return {};
    }
    return data(createIndex(row, 0), keys.first());
}

QHash<int, QByteArray> ConnectionsModel::roleNames() const
{
    return {
        {ProtocolRole, "protocol"},
        {LocalAddressRole, "localAddress"},
        {ForeignAddressRole, "foreignAddress"},
        {StatusRole, "status"},
        {PidRole, "pid"},
        {ProgramRole, "program"},
    };
}

void ConnectionsModel::refreshConnections()
{
    if (m_queryRunning)
    {
        NetstatClient::self()->setStatus("Netstat client is bussy");
        return;
    }

    m_queryRunning = true;

    KAuth::ExecuteJob *job = m_queryAction.execute();
    connect(job, &KAuth::ExecuteJob::finished, [this] (KJob *kjob)
    {
        auto job = qobject_cast<KAuth::ExecuteJob *>(kjob);
        if (!job->error())
        {
            beginResetModel();
            m_connectionsData = job->data().value("connections", QVariantList()).toList();
            endResetModel();
            NetstatClient::self()->setStatus({});
        } else {
            NetstatClient::self()->setStatus(QStringLiteral("BACKEND ERROR: ") + job->error() + QStringLiteral(" ") + job->errorText());
        }
        m_queryRunning = false;
    });

    job->start();
}

