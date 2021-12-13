#include "firewalldlogmodel.h"

FirewalldLogModel::FirewalldLogModel(QObject *parent)
    : LogListModel(parent)
{

}

void FirewalldLogModel::addRawLogs(const QStringList &rawLogsList)
{
    Q_UNUSED(rawLogsList);
    // TODO: Implement-me. look at UfwLogModel for inspiration.
}
