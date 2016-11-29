#ifndef RPCCLIENT_H
#define RPCCLIENT_H

#include <QDialog>
QT_BEGIN_NAMESPACE
class QNetworkAccessManager;
class QAuthenticator;
class QNetworkReply;
QT_END_NAMESPACE

class RpcClient
{
    Q_OBJECT

public:
   

    explicit RpcClient();
    ~RpcClient();

	void setEndpoint(const QString &endPoint);
    void setUsername(const QString &username);
	void setPassword(const QString &password);
	
private:
	QString m_endpoint;
    QString m_username;
    QString m_password;

private:
	void sendRequest(QNetworkAccessManager *nam, const QString &request, const QString &response);
private Q_SLOTS:
	 virtual void handleAuthenticationRequired(QNetworkReply *reply, QAuthenticator * authenticator);
};

#endif // RPCCLIENT_H
