#if QT_VERSION < 0x050000
#include <QUrl>
#else
#include <QUrlQuery>
#endif
using namespace std;
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QAuthenticator>
#include <QDebug>
#include "qjsonrpcclient.h"
RpcClient::RpcClient()
{
	m_endpoint = "";
	m_username = "";
	m_password = "";
}
RpcClient::~RpcClient()
{
}
void RpcClient::setEndpoint(const QString &endpoint) {
    m_endpoint = endpoint;
}
void RpcClient::setUsername(const QString &username) {
    m_username = username;
}

void RpcClient::setPassword(const QString &password) {
    m_password = password;
}
void RpcClient::sendRequest(QNetworkAccessManager *nam, const QString &method, const QString &param) {
	
	connect(nam, SIGNAL(authenticationRequired(QNetworkReply*, QAuthenticator*)), this, SLOT(handleAuthenticationRequired(QNetworkReply*, QAuthenticator*)));
	
	QString data = "{\"jsonrpc\": \"1.0\", \"id\":\"syscoinRpcClient\", ""\"method\": \"" + method + "\", \"params\": [" + param + "] }";
	QJsonDocument doc = QJsonDocument::fromJson(data.toUtf8());
	QByteArray postData = doc.toJson();
	QUrl url(m_endpoint);
	QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Accept", "application/json-rpc");
	nam->post(request, postData);
}
void RpcClient::handleAuthenticationRequired(QNetworkReply *reply, QAuthenticator * authenticator)
{
    Q_UNUSED(reply)
    authenticator->setUser(m_username);
    authenticator->setPassword(m_password);
} 
