#ifndef ZECRpcClient_H
#define ZECRpcClient_H

#include "qjsonrpcclient.h"
QT_BEGIN_NAMESPACE
class QNetworkAccessManager;
QT_END_NAMESPACE

class ZecRpcClient
{
    Q_OBJECT

public:
 
    explicit ZecRpcClient();
    ~ZecRpcClient();
	void sendRequest(const QNetworkAccessManager *nam, const QString &request, const QString &param) 
private:
	RpcClient m_client;

};

#endif // ZECRpcClient_H
