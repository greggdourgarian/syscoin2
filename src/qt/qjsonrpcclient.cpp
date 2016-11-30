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
	QString data = "{\"jsonrpc\": \"1.0\", \"id\":\"SyscoinRPCClient\", ""\"method\": \"" + method + "\", \"params\": [" + param + "] }";
	QJsonDocument doc = QJsonDocument::fromJson(data.toUtf8());
	QByteArray postData = doc.toJson();
	QUrl url(m_endpoint);
	QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Accept", "application/json-rpc");
	// HTTP Basic authentication header value: base64(username:password)
	QString concatenated = m_username + ":" + m_password;
	QByteArray data = concatenated.toLocal8Bit().toBase64();
	QString headerData = "Basic " + data;
	request.setRawHeader("Authorization", headerData.toLocal8Bit());
	nam->post(request, postData);
}

