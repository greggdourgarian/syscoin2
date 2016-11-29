
#include "qzecjsonrpcclient.h"
#include <QSettings>

ZecRpcClient::ZecRpcClient()
{
	QSettings settings;
	m_client.setEndpoint(settings.value("btcEndPoint", "").toString());
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