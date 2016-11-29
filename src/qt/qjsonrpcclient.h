#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include <QDialog>
#include "qjsonrpchttpclient.h"
QT_BEGIN_NAMESPACE
class QAuthenticator;
class QNetworkReply;
QT_END_NAMESPACE


/** Widget that shows a list of owned aliases.
  */
class HttpClient : public QJsonRpcHttpClient
{
    Q_OBJECT

public:
   

    explicit HttpClient(const QString &endpoint, QObject *parent = 0);
    ~HttpClient();


    void setUsername(const QString &username);
	void setPassword(const QString &password);
	
private:
    QString m_username;
    QString m_password;

private:
	void sendRequest(const QString &request, QString &response);
private Q_SLOTS:
	 virtual void handleAuthenticationRequired(QNetworkReply *reply, QAuthenticator * authenticator);

};

#endif // HTTPCLIENT_H
