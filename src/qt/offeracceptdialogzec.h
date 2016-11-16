#ifndef OFFERACCEPTDIALOGZEC_H
#define OFFERACCEPTDIALOGZEC_H
#include "walletmodel.h"
#include <QDialog>
#include <QImage>
#include <QLabel>
#include "amount.h"
class PlatformStyle;
class WalletModel;
QT_BEGIN_NAMESPACE
class QNetworkReply;
QT_END_NAMESPACE
namespace Ui {
    class OfferAcceptDialogZEC;
}
class OfferAcceptDialogZEC : public QDialog
{
    Q_OBJECT

public:
    explicit OfferAcceptDialogZEC(WalletModel* model, const PlatformStyle *platformStyle, QString alias, QString offer, QString quantity, QString notes, QString title, QString currencyCode, QString strPrice, QString sellerAlias, QString address, QWidget *parent=0);
    ~OfferAcceptDialogZEC();
	void CheckPaymentInZEC();
    bool getPaymentStatus();
	void SetupQRCode(const QString&price);
	void convertAddress(QString& address);
private:
	void setupEscrowCheckboxState();
	WalletModel* walletModel;
	const PlatformStyle *platformStyle;
    Ui::OfferAcceptDialogZEC *ui;
	SendCoinsRecipient info;
	QString quantity;
	QString notes;
	QString qstrPrice;
	QString title;
	QString offer;
	QString acceptGuid;
	QString sellerAlias;
	QString address;
	QString multisigaddress;
	QString alias;
	QString rawZECTx;
	QString m_buttonText;
	double dblPrice;
	bool offerPaid; 
	QString m_redeemScript;	
	qint64 m_height;

private Q_SLOTS:
	void on_cancelButton_clicked();
    void tryAcceptOffer();
	void onEscrowCheckBoxChanged(bool);
    void acceptOffer();
	void acceptEscrow();
	void openZECWallet();
	void slotConfirmedFinished(QNetworkReply *);
	
};

#endif // OFFERACCEPTDIALOGZEC_H
