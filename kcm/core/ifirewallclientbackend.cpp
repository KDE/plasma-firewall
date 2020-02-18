#include "ifirewallclientbackend.h"

IFirewallClientBackend::IFirewallClientBackend(FirewallClient *parent)
    : m_parent(parent)
{

};

FirewallClient *IFirewallClientBackend::parentClient() const
{
    return m_parent;
}

void IFirewallClientBackend::setProfiles(const QList<Entry> &profiles)
{
    std::sort(std::begin(m_profiles), std::end(m_profiles));
    m_profiles = profiles;
}

Entry IFirewallClientBackend::profileByName(const QString &name)
{
    for(const auto entry : qAsConst(m_profiles)) {
        if (entry.name == name) {
            return entry;
        }
    }
    return Entry({});
}
