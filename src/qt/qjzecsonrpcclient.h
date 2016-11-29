#ifndef ZECHTTPCLIENT_H
#define ZECHTTPCLIENT_H

#include "qjsonhttpclient.h"
QT_BEGIN_NAMESPACE
QT_END_NAMESPACE

class ZecHttpClient
{
    Q_OBJECT

public:
 
    explicit ZecHttpClient();
    ~ZecHttpClient();
	void sendRequest(const QString &request, QString &response);
private:
	HttpClient m_client;
};

#endif // ZECHTTPCLIENT_H
