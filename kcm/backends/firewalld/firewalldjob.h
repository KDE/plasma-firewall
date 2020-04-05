#include <KJob>

#ifndef FIREWALLDJOB_H
#define FIREWALLDJOB_H


class FirewalldJob : public KJob {

    ~FirewalldJob(){};
    public:
    void start() {};
    void setErrorText(const QString &message ) {
        KJob::setErrorText(message);
    };

};


#endif
