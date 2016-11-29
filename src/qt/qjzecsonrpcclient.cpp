
#include "qzecjsonrpcclient.h"
#include <QSettings>

ZecHttpClient::ZecHttpClient()
{
	m_client = HttpClient(settings.value("zecEndPoint", "").toString());
	m_client.setUsername(settings.value("zecRPCLogin", "").toString());
	m_client.setPassword(settings.value("zecRPCPassword", "").toString());
}
void ZecHttpClient::sendRequest(const QString &request, QString &response)
{
	m_client.sendRequest(request, response);
}
ZecHttpClient::~ZecHttpClient()
{
}