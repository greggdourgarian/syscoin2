
#include <QAuthenticator>
#include <QDebug>
#include "qjsonrpcclient.h"
HttpClient::HttpClient(const QString &endpoint, QObject *parent) :
     : QJsonRpcHttpClient(endpoint, parent)
{
	m_username = "";
	m_password = "";
}
HttpClient::~HttpClient()
{
}
void HttpClient::setUsername(const QString &username) {
    m_username = username;
}

void HttpClient::setPassword(const QString &password) {
    m_password = password;
}
void HttpClient::sendRequest(const QString &request, QString& jsonResponse) {
    QJsonRpcMessage message = QJsonRpcMessage::createRequest(request);
    QJsonRpcMessage response = sendMessageBlocking(message);
    if (response.type() == QJsonRpcMessage::Error) {
        qDebug() << response.errorData();
    }
	jsonResponse = response.toJson();
    qDebug() << jsonResponse;
}
void HttpClient::handleAuthenticationRequired(QNetworkReply *reply, QAuthenticator * authenticator)
{
    Q_UNUSED(reply)
    authenticator->setUser(m_username);
    authenticator->setPassword(m_password);
} 
