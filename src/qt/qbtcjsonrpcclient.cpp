
#include "qbtcjsonrpcclient.h"
#include <QSettings>

BtcRpcClient::BtcRpcClient()
{
	QSettings settings;
	m_client.setEndpoint(settings.value("btcEndPoint", "").toString());
	m_client.setUsername(settings.value("btcRPCLogin", "").toString());
	m_client.setPassword(settings.value("btcRPCPassword", "").toString());
}
void BtcRpcClient::sendRequest(QNetworkAccessManager *nam, const QString &request, const QString &param)
{
	m_client.sendRequest(nam, request, param);
}
BtcRpcClient::~BtcRpcClient()
{
}