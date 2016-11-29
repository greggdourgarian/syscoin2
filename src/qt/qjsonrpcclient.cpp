#if QT_VERSION < 0x050000
#include <QUrl>
#else
#include <QUrlQuery>
#endif
using namespace std;
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QAuthenticator>
#include <QDebug>
#include "qjsonrpcclient.h"
RpcClient::RpcClient(const QString &endpoint, QObject *parent)
{
	m_endpoint = endpoint;
	m_username = "";
	m_password = "";
}
RpcClient::~RpcClient()
{
}
void RpcClient::setUsername(const QString &username) {
    m_username = username;
}

void RpcClient::setPassword(const QString &password) {
    m_password = password;
}
void RpcClient::sendRequest(const QNetworkAccessManager *nam, const QString &request, const QString &param) {

	QString data = "{\"jsonrpc\": \"1.0\", \"id\":\"syscoinRpcClient\", ""\"method\": \"" + request + "\", \"params\": [" + param + "] }";
	QUrl url(m_endpoint);
	QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Accept", "application/json-rpc");
	nam->post(request, data);
}
void RpcClient::handleAuthenticationRequired(QNetworkReply *reply, QAuthenticator * authenticator)
{
    Q_UNUSED(reply)
    authenticator->setUser(m_username);
    authenticator->setPassword(m_password);
} 
