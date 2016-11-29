
#include "qzecjsonrpcclient.h"
#include <QSettings>

ZecRpcClient::ZecRpcClient()
{
	m_client = RpcClient(settings.value("zecEndPoint", "").toString());
	m_client.setUsername(settings.value("zecRPCLogin", "").toString());
	m_client.setPassword(settings.value("zecRPCPassword", "").toString());
}
void ZecRpcClient::sendRequest(QNetworkAccessManager *nam, const QString &request, const QString &param)
{
	m_client.sendRequest(nam, request, param);
}
ZecRpcClient::~ZecRpcClient()
{
}