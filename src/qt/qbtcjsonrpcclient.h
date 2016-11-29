#ifndef BTCRPCCLIENT_H
#define BTCRPCCLIENT_H

#include "qjsonrpcclient.h"
QT_BEGIN_NAMESPACE
class QNetworkAccessManager;
QT_END_NAMESPACE

class BtcRpcClient
{
public:
 
    explicit BtcRpcClient();
    ~BtcRpcClient();
	void sendRequest(QNetworkAccessManager *nam, const QString &request, const QString &param);
private:
	RpcClient m_client;

};

#endif // BTCRPCCLIENT_H
