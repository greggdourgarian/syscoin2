#ifndef ZECRPCCLIENT_H
#define ZECRPCCLIENT_H

#include "qjsonrpcclient.h"
QT_BEGIN_NAMESPACE
class QNetworkAccessManager;
QT_END_NAMESPACE

class ZecRpcClient
{
public:
 
    explicit ZecRpcClient();
    ~ZecRpcClient();
	void sendRequest(QNetworkAccessManager *nam, const QString &request, const QString &param); 
private:
	RpcClient m_client;

};

#endif // ZECRPCCLIENT_H