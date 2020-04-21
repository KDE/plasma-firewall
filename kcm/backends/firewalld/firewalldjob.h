
#ifndef FIREWALLDJOB_H
#define FIREWALLDJOB_H

#include <KJob>

class FirewalldJob : public KJob {

public:
    FirewalldJob();
    ~FirewalldJob();
    void start() override;
    void setErrorText(const QString &message ) {
        KJob::setErrorText(message);
    };

};

FirewalldJob::FirewalldJob() {};
FirewalldJob::~FirewalldJob() {};
void FirewalldJob::start() {};

#endif
