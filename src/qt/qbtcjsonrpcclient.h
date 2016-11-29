#ifndef BTCRpcClient_H
#define BTCRpcClient_H

#include "qjsonrpcclient.h"
QT_BEGIN_NAMESPACE
class QNetworkAccessManager;
QT_END_NAMESPACE

class BtcRpcClient
{
    Q_OBJECT

public:
 
    explicit BtcRpcClient();
    ~BtcRpcClient();
	void sendRequest(const QNetworkAccessManager *nam, const QString &request, const QString &param) 
private:
	RpcClient m_client;

};

#endif // BTCRpcClient_H
