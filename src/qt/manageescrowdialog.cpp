#include "manageescrowdialog.h"
#include "ui_manageescrowdialog.h"

#include "guiutil.h"
#include "syscoingui.h"
#include "platformstyle.h"
#include "ui_interface.h"
#include <QMessageBox>
#include "rpc/server.h"
#include "walletmodel.h"
#if QT_VERSION < 0x050000
#include <QUrl>
#else
#include <QUrlQuery>
#endif
using namespace std;
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSettings>
extern CRPCTable tableRPC;
ManageEscrowDialog::ManageEscrowDialog(WalletModel* model, const QString &escrow, QWidget *parent) :
    QDialog(parent),
	walletModel(model),
    ui(new Ui::ManageEscrowDialog), escrow(escrow)
{
    ui->setupUi(this);
	refundWarningStr = releaseWarningStr = "";
	QString theme = GUIUtil::getThemeName();  
	ui->aboutEscrow->setPixmap(QPixmap(":/images/" + theme + "/escrow"));
	QString buyer, seller, arbiter, status, offertitle, total;
	ui->primaryLabel->setVisible(false);
	ui->primaryRating->setVisible(false);
	ui->primaryFeedback->setVisible(false);
	ui->secondaryLabel->setVisible(false);
	ui->secondaryRating->setVisible(false);
	ui->secondaryFeedback->setVisible(false);
	ui->btcButton->setVisible(false);
	ui->btcButton->setEnabled(false);
	if(!loadEscrow(escrow, buyer, seller, arbiter, status, offertitle, total, m_btctxid, m_redeemTxId))
	{
		ui->manageInfo2->setText(tr("Cannot find this escrow on the network, please try again later."));
		ui->releaseButton->setEnabled(false);
		ui->refundButton->setEnabled(false);
		return;
	}

	escrowRoleType = findYourEscrowRoleFromAliases(buyer, seller, arbiter);
	ui->manageInfo->setText(tr("You are managing escrow ID: <b>%1</b> of an offer for <b>%2</b> totalling <b>%3</b>. The buyer is <b>%4</b>, merchant is <b>%5</b> and arbiter is <b>%6</b>").arg(escrow).arg(offertitle).arg(total).arg(buyer).arg(seller).arg(arbiter));
	if(escrowRoleType == None)
	{
		ui->manageInfo2->setText(tr("You cannot manage this escrow because you do not own one of either the buyer, merchant or arbiter aliases."));
		ui->releaseButton->setEnabled(false);
		ui->refundButton->setEnabled(false);
	}
	else if(status == "in escrow")
	{
		if(escrowRoleType == Buyer)
		{
			ui->manageInfo2->setText(tr("You are the <b>buyer</b> of the offer held in escrow, you may release the coins to the merchant once you have confirmed that you have recieved the item as per the description of the offer."));
			ui->refundButton->setEnabled(false);
		}
		else if(escrowRoleType == Seller)
		{
			ui->manageInfo2->setText(tr("You are the <b>merchant</b> of the offer held in escrow, you may refund the coins back to the buyer."));
			ui->releaseButton->setEnabled(false);
		}
		else if(escrowRoleType == Arbiter)
		{
			ui->manageInfo2->setText(tr("You are the <b>arbiter</b> of the offer held in escrow, you may refund the coins back to the buyer if you have evidence that the merchant did not honour the agreement to ship the offer item. You may also release the coins to the merchant if the buyer has not released in a timely manor. You may use Syscoin messages to communicate with the buyer and merchant to ensure you have adequate proof for your decision."));
		}

	}
	else if(status == "escrow released")
	{
		if(m_btctxid.size() > 0)
		{
			ui->btcButton->setVisible(true);
		}
		if(escrowRoleType == Buyer)
		{
			ui->manageInfo2->setText(tr("You are the <b>buyer</b> of the offer held in escrow. The escrow has been released to the merchant. You may communicate with your arbiter or merchant via Syscoin messages. You may leave feedback after the money is claimed by the merchant."));
			ui->refundButton->setEnabled(false);
			ui->releaseButton->setEnabled(false);
		}
		else if(escrowRoleType == Seller)
		{
			ui->manageInfo2->setText(tr("You are the <b>merchant</b> of the offer held in escrow. The payment of coins have been released to you, you may claim them now. After claiming, please return to this dialog and provide feedback for this escrow transaction."));
			ui->releaseButton->setText(tr("Claim Payment"));
			ui->refundButton->setEnabled(false);

		}
		else if(escrowRoleType == Arbiter)
		{
			ui->manageInfo2->setText(tr("You are the <b>arbiter</b> of the offer held in escrow. The escrow has been released to the merchant. You may re-release this escrow if there are any problems claiming the coins by the merchant. If you were the one to release the coins you will recieve a commission as soon as the merchant claims his payment. You may leave feedback after the money is claimed by the merchant."));
			releaseWarningStr = tr("Warning: Payment has already been released, are you sure you wish to re-release payment to the merchant?");
			ui->refundButton->setEnabled(false);
		}
	}
	else if(status == "escrow refunded")
	{
		if(m_btctxid.size() > 0)
		{
			ui->btcButton->setVisible(true);
		}
		if(escrowRoleType == Buyer)
		{
			ui->manageInfo2->setText(tr("You are the <b>buyer</b> of the offer held in escrow. The coins have been refunded back to you, you may claim them now. After claiming, please return to this dialog and provide feedback for this escrow transaction."));
			ui->refundButton->setText(tr("Claim Refund"));
			ui->releaseButton->setEnabled(false);
		}
		else if(escrowRoleType == Seller)
		{
			ui->manageInfo2->setText(tr("You are the <b>merchant</b> of the offer held in escrow. The escrow has been refunded back to the buyer. You may leave feedback after the money is claimed by the buyer."));
			ui->refundButton->setEnabled(false);
			ui->releaseButton->setEnabled(false);

		}
		else if(escrowRoleType == Arbiter)
		{
			ui->manageInfo2->setText(tr("You are the <b>arbiter</b> of the offer held in escrow. The escrow has been refunded back to the buyer. You may re-issue a refund if there are any problems claiming the coins by the buyer. If you were the one to refund the coins you will recieve a commission as soon as the buyer claims his refund. You may leave feedback after the money is claimed by the buyer."));
			ui->releaseButton->setEnabled(false);
			refundWarningStr = tr("Warning: Payment has already been refunded, are you sure you wish to re-refund payment back to the buyer?");	
		}
	}
	else if(status == "escrow release complete")
	{		
		if(m_btctxid.size() > 0)
		{
			ui->btcButton->setVisible(true);
			if(m_redeemTxId.size() > 0)
				ui->btcButton->setEnabled(true);
		}
		ui->manageInfo2->setText(tr("The escrow has been successfully claimed by the merchant. The escrow is complete."));
		ui->refundButton->setEnabled(false);
		ui->refundButton->setVisible(false);
		ui->primaryLabel->setVisible(true);
		ui->primaryRating->setVisible(true);
		ui->primaryFeedback->setVisible(true);
		ui->secondaryLabel->setVisible(true);
		ui->secondaryRating->setVisible(true);
		ui->secondaryFeedback->setVisible(true);
		ui->releaseButton->setText(tr("Leave Feedback"));

		if(escrowRoleType == Buyer)
		{
			ui->primaryLabel->setText("Choose a rating for the merchant (1-5) or leave at 0 for no rating. Below please give feedback to the merchant.");
			ui->secondaryLabel->setText("Choose a rating for the arbiter (1-5) or leave at 0 for no rating. Below please give feedback to the arbiter. Skip if escrow arbiter was not involved.");
		}
		else if(escrowRoleType == Seller)
		{
			ui->primaryLabel->setText("Choose a rating for the buyer (1-5) or leave at 0 for no rating. Below please give feedback to the buyer.");
			ui->secondaryLabel->setText("Choose a rating for the arbiter (1-5) or leave at 0 for no rating. Below please give feedback to the arbiter. Skip if escrow arbiter was not involved.");

		}
		else if(escrowRoleType == Arbiter)
		{
			ui->primaryLabel->setText("Choose a rating for the buyer (1-5) or leave at 0 for no rating. Below please give feedback to the buyer.");
			ui->secondaryLabel->setText("Choose a rating for the merchant (1-5) or leave at 0 for no rating. Below please give feedback to the merchant.");	
		}
	}
	else if(status == "escrow refund complete")
	{	
		
		if(m_btctxid.size() > 0)
		{
			ui->btcButton->setVisible(true);
			if(m_redeemTxId.size() > 0)
				ui->btcButton->setEnabled(true);
		}	
		ui->manageInfo2->setText(tr("The escrow has been successfully refunded to the buyer. The escrow is complete."));
		ui->refundButton->setEnabled(false);
		ui->refundButton->setVisible(false);
		ui->primaryLabel->setVisible(true);
		ui->primaryRating->setVisible(true);
		ui->primaryFeedback->setVisible(true);
		ui->secondaryLabel->setVisible(true);
		ui->secondaryRating->setVisible(true);
		ui->secondaryFeedback->setVisible(true);
		ui->releaseButton->setText(tr("Leave Feedback"));
		if(escrowRoleType == Buyer)
		{
			ui->primaryLabel->setText("Choose a rating for the merchant (1-5) or leave at 0 for no rating. Below please give feedback to the merchant.");
			ui->secondaryLabel->setText("Choose a rating for the arbiter (1-5) or leave at 0 for no rating. Below please give feedback to the arbiter. Skip if escrow arbiter was not involved.");	
		}
		else if(escrowRoleType == Seller)
		{
			ui->primaryLabel->setText("Choose a rating for the buyer (1-5) or leave at 0 for no rating. Below please give feedback to the buyer.");
			ui->secondaryLabel->setText("Choose a rating for the arbiter (1-5) or leave at 0 for no rating. Below please give feedback to the arbiter. Skip if escrow arbiter was not involved.");
		}
		else if(escrowRoleType == Arbiter)
		{
			ui->primaryLabel->setText("Choose a rating for the buyer (1-5) or leave at 0 for no rating. Below please give feedback to the buyer.");
			ui->secondaryLabel->setText("Choose a rating for the merchant (1-5) or leave at 0 for no rating. Below please give feedback to the merchant.");	
		}

	}
	else
	{
		ui->manageInfo2->setText(tr("The escrow status was not recognized. Please contact the Syscoin team."));
		ui->refundButton->setEnabled(false);
		ui->releaseButton->setEnabled(false);
	}
}
bool ManageEscrowDialog::loadEscrow(const QString &escrow, QString &buyer, QString &seller, QString &arbiter, QString &status, QString &offertitle, QString &total, QString &btctxid, QString &redeemtxid)
{
	QSettings settings;
	string strMethod = string("escrowinfo");
    UniValue params(UniValue::VARR); 
	params.push_back(escrow.toStdString());
	UniValue result ;
	string name_str;
	try {
		result = tableRPC.execute(strMethod, params);
		if (result.type() == UniValue::COBJ)
		{
			const UniValue& o = result.get_obj();
	
			const UniValue& name_value = find_value(o, "escrow");
			if (name_value.type() == UniValue::VSTR)
				name_str = name_value.get_str();
			if(QString::fromStdString(name_str) != escrow)
				return false;
			const UniValue& seller_value = find_value(o, "seller");
			if (seller_value.type() == UniValue::VSTR)
				seller = QString::fromStdString(seller_value.get_str());
			const UniValue& arbiter_value = find_value(o, "arbiter");
			if (arbiter_value.type() == UniValue::VSTR)
				arbiter = QString::fromStdString(arbiter_value.get_str());
			const UniValue& buyer_value = find_value(o, "buyer");
			if (buyer_value.type() == UniValue::VSTR)
				buyer = QString::fromStdString(buyer_value.get_str());
			const UniValue& offertitle_value = find_value(o, "offertitle");
			if (offertitle_value.type() == UniValue::VSTR)
				offertitle = QString::fromStdString(offertitle_value.get_str());
			string currency_str = "";
			const UniValue& currency_value = find_value(o, "currency");
			if (currency_value.type() == UniValue::VSTR)
				currency_str = currency_value.get_str();
			const UniValue& total_value = find_value(o, "total");
			if (total_value.type() == UniValue::VSTR)
				total = QString::fromStdString(total_value.get_str() + string(" ") + currency_str);
			const UniValue& status_value = find_value(o, "status");
			if (status_value.type() == UniValue::VSTR)
				status = QString::fromStdString(status_value.get_str());
			const UniValue& btctxid_value = find_value(o, "btctxid");
			if (btctxid_value.type() == UniValue::VSTR)
				btctxid = QString::fromStdString(btctxid_value.get_str());
			const UniValue& redeemtxid_value = find_value(o, "redeem_txid");
			if (redeemtxid_value.type() == UniValue::VSTR)
				redeemtxid = QString::fromStdString(redeemtxid_value.get_str());
			return true;
		}
	}
	catch (UniValue& objError)
	{
		return false;
	}
	catch(std::exception& e)
	{
		return false;
	}
	return false;
}
QString ManageEscrowDialog::EscrowRoleTypeToString(const EscrowRoleType& escrowType)
{
	if(escrowType == Arbiter)
		return tr("arbiter");
	else if(escrowType == Seller)
		return tr("seller");
	else if(escrowType == Buyer)
		return tr("buyer");
	else
		return tr("none");
}
void ManageEscrowDialog::on_cancelButton_clicked()
{
    reject();
}
void ManageEscrowDialog::on_btcButton_clicked()
{
    CheckPaymentInBTC();
}

ManageEscrowDialog::~ManageEscrowDialog()
{
    delete ui;
}
void ManageEscrowDialog::onLeaveFeedback()
{
	UniValue params(UniValue::VARR);
	string strMethod = string("escrowfeedback");
	params.push_back(escrow.toStdString());
	params.push_back(EscrowRoleTypeToString(escrowRoleType).toStdString());
	params.push_back(ui->primaryFeedback->toPlainText().toStdString());
	params.push_back(ui->primaryRating->cleanText().toStdString());
	params.push_back(ui->secondaryFeedback->toPlainText().toStdString());
	params.push_back(ui->secondaryRating->cleanText().toStdString());
	try {
		UniValue result = tableRPC.execute(strMethod, params);
		const UniValue& resArray = result.get_array();
		if(resArray.size() > 1)
		{
			const UniValue& complete_value = resArray[1];
			bool bComplete = false;
			if (complete_value.isStr())
				bComplete = complete_value.get_str() == "true";
			if(!bComplete)
			{
				string hex_str = resArray[0].get_str();
				GUIUtil::setClipboard(QString::fromStdString(hex_str));
				QMessageBox::information(this, windowTitle(),
					tr("This transaction requires more signatures. Transaction hex has been copied to your clipboard for your reference. Please provide it to a signee that has not yet signed."),
						QMessageBox::Ok, QMessageBox::Ok);
				return;
			}
		}
		QMessageBox::information(this, windowTitle(),
		tr("Thank you for your feedback!"),
			QMessageBox::Ok, QMessageBox::Ok);
		ManageEscrowDialog::accept();
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error sending feedback: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception sending feedbackescrow"),
			QMessageBox::Ok, QMessageBox::Ok);
	}	
}
bool ManageEscrowDialog::CompleteEscrowRelease()
{
	UniValue params(UniValue::VARR);
	string strMethod = string("escrowcompleterelease");
	params.push_back(escrow.toStdString());
	params.push_back(this->m_rawTx.toStdString());

	try {
		UniValue result = tableRPC.execute(strMethod, params);

		if(m_btctxid.size() > 0)
		{
			QMessageBox::information(this, windowTitle(),
			tr("Escrow release completed successfully! Payment was found on the Bitcoin blockchain Transaction ID <b>%1</b>. You may click on the <b>Check BTC Payment</b> button to check to see if it has confirmed.").arg(m_redeemTxId),
				QMessageBox::Ok, QMessageBox::Ok);
		}
		else
		{
			const UniValue& resArray = result.get_array();
			if(resArray.size() > 1)
			{
				const UniValue& complete_value = resArray[1];
				bool bComplete = false;
				if (complete_value.isStr())
					bComplete = complete_value.get_str() == "true";
				if(!bComplete)
				{
					string hex_str = resArray[0].get_str();
					GUIUtil::setClipboard(QString::fromStdString(hex_str));
					QMessageBox::information(this, windowTitle(),
						tr("This transaction requires more signatures. Transaction hex has been copied to your clipboard for your reference. Please provide it to a signee that has not yet signed."),
							QMessageBox::Ok, QMessageBox::Ok);
					return true;
				}
			}
			QMessageBox::information(this, windowTitle(),
			tr("Escrow release completed successfully! "),
				QMessageBox::Ok, QMessageBox::Ok);
		}
		return true;
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error completing release: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception completing release"),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	return false;
}
bool ManageEscrowDialog::CompleteEscrowRefund()
{
	UniValue params(UniValue::VARR);
	string strMethod = string("escrowcompleterefund");
	params.push_back(escrow.toStdString());
	params.push_back(this->m_rawTx.toStdString());

	try {
		UniValue result = tableRPC.execute(strMethod, params);

		if(m_btctxid.size() > 0)
		{
			QMessageBox::information(this, windowTitle(),
			tr("Escrow refund completed successfully! Payment was found on the Bitcoin blockchain Transaction ID <b>%1</b>. You may click on the <b>Check BTC Payment</b> button to check to see if the payment has confirmed.").arg(m_redeemTxId),
				QMessageBox::Ok, QMessageBox::Ok);
		}
		else
		{
			const UniValue& resArray = result.get_array();
			if(resArray.size() > 1)
			{
				const UniValue& complete_value = resArray[1];
				bool bComplete = false;
				if (complete_value.isStr())
					bComplete = complete_value.get_str() == "true";
				if(!bComplete)
				{
					string hex_str = resArray[0].get_str();
					GUIUtil::setClipboard(QString::fromStdString(hex_str));
					QMessageBox::information(this, windowTitle(),
						tr("This transaction requires more signatures. Transaction hex has been copied to your clipboard for your reference. Please provide it to a signee that has not yet signed."),
							QMessageBox::Ok, QMessageBox::Ok);
					return true;
				}
			}
			QMessageBox::information(this, windowTitle(),
			tr("Escrow refund completed successfully!"),
				QMessageBox::Ok, QMessageBox::Ok);
		}
		return true;
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error completing refund: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception completing refund"),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	return false;
}
void ManageEscrowDialog::slotConfirmedFinished(QNetworkReply * reply){
	if(reply->error() != QNetworkReply::NoError) {
		if(m_buttontext == tr("Claim Payment"))
		{
			ui->releaseButton->setText(m_buttontext);
			ui->releaseButton->setEnabled(true);
		}
		else if(m_buttontext == tr("Claim Refund"))
		{
			ui->refundButton->setText(m_buttontext);
			ui->refundButton->setEnabled(true);	
		}
        QMessageBox::critical(this, windowTitle(),
			tr("Could not send raw escrow transaction to the Bitcoin blockchain, error: ") + reply->errorString(),
                QMessageBox::Ok, QMessageBox::Ok);
		reply->deleteLater();
		return;
	}
	
	if(m_buttontext == tr("Claim Payment"))
	{
		if(!CompleteEscrowRelease())
		{
			if(m_buttontext == tr("Claim Payment"))
			{
				ui->releaseButton->setText(m_buttontext);
				ui->releaseButton->setEnabled(true);
			}
			else if(m_buttontext == tr("Claim Refund"))
			{
				ui->refundButton->setText(m_buttontext);
				ui->refundButton->setEnabled(true);	
			}
			reply->deleteLater();
			return;
		}
	}
	else if(m_buttontext == tr("Claim Refund"))
	{
		if(!CompleteEscrowRefund())
		{
			if(m_buttontext == tr("Claim Payment"))
			{
				ui->releaseButton->setText(m_buttontext);
				ui->releaseButton->setEnabled(true);
			}
			else if(m_buttontext == tr("Claim Refund"))
			{
				ui->refundButton->setText(m_buttontext);
				ui->refundButton->setEnabled(true);	
			}
			reply->deleteLater();
			return;
		}
	}
	if(m_btctxid.size() > 0)
	{
		ui->btcButton->setVisible(true);
		if(m_redeemTxId.size() > 0)
			ui->btcButton->setEnabled(true);
	}
	if(m_buttontext == tr("Claim Payment"))
	{
		ui->releaseButton->setText(m_buttontext);
		ui->releaseButton->setEnabled(false);
	}
	else if(m_buttontext == tr("Claim Refund"))
	{
		ui->refundButton->setText(m_buttontext);
		ui->refundButton->setEnabled(false);	
	}
	reply->deleteLater();
}
void ManageEscrowDialog::SendRawTxBTC()
{
	QNetworkAccessManager *nam = new QNetworkAccessManager(this); 
	connect(nam, SIGNAL(finished(QNetworkReply *)), this, SLOT(slotConfirmedFinished(QNetworkReply *)));
	QUrlQuery postData;
	postData.addQueryItem("hex", m_rawTx);
	QUrl url("http://btc.blockr.io/api/v1/tx/push");
	QNetworkRequest request(url);
	request.setHeader(QNetworkRequest::ContentTypeHeader, 
		"application/x-www-form-urlencoded");
	nam->post(request, postData.toString(QUrl::FullyEncoded).toUtf8());
}
void ManageEscrowDialog::slotConfirmedFinishedCheck(QNetworkReply * reply){
	if(reply->error() != QNetworkReply::NoError) {
		ui->btcButton->setText(m_buttontext);
		GUIUtil::setClipboard(m_redeemTxId);
        QMessageBox::critical(this, windowTitle(),
            tr("Could not find escrow payment on the Bitcoin blockchain, please ensure that the payment transaction ID <b>%1</b> has been confirmed on the network. Payment ID has been copied to your clipboard for your reference.").arg(m_redeemTxId),
                QMessageBox::Ok, QMessageBox::Ok);
		reply->deleteLater();
		return;
	}
	double valueAmount = 0;
	unsigned int time;
	int height;
			
	QByteArray bytes = reply->readAll();
	QString str = QString::fromUtf8(bytes.data(), bytes.size());
	UniValue outerValue;
	bool read = outerValue.read(str.toStdString());
	if (read)
	{
		UniValue outerObj = outerValue.get_obj();
		UniValue statusValue = find_value(outerObj, "status");
		if (statusValue.isStr())
		{
			if(statusValue.get_str() != "success")
			{
				ui->btcButton->setText(m_buttontext);
				QMessageBox::critical(this, windowTitle(),
					tr("Transaction status not successful: ") + QString::fromStdString(statusValue.get_str()),
						QMessageBox::Ok, QMessageBox::Ok);
				reply->deleteLater();
				return;
			}
		}
		else
		{
			ui->btcButton->setText(m_buttontext);
			QMessageBox::critical(this, windowTitle(),
				tr("Transaction status not successful: ") + QString::fromStdString(statusValue.get_str()),
					QMessageBox::Ok, QMessageBox::Ok);
			reply->deleteLater();	
			return;
		}
		UniValue dataObj1 = find_value(outerObj, "data").get_obj();
		UniValue dataObj = find_value(dataObj1, "tx").get_obj();
		UniValue timeValue = find_value(dataObj, "time");
		if (timeValue.isNum())
			time = timeValue.get_int();
		QDateTime timestamp;
		timestamp.setTime_t(time);

		UniValue unconfirmedValue = find_value(dataObj, "confirmations");
		if (unconfirmedValue.isNum())
		{
			int confirmations = unconfirmedValue.get_int();
			if(confirmations >= 1)
			{
				GUIUtil::setClipboard(m_redeemTxId);
				QMessageBox::information(this, windowTitle(),
					tr("Escrow payment ID <b>%1</b> found at <b>%2</b> in the Bitcoin blockchain and has <b>%3</b> confirmations. Payment ID has been copied to your clipboard for your reference.").arg(m_redeemTxId).arg(timestamp.toString(Qt::SystemLocaleShortDate)).arg(QString::number(confirmations)),
					QMessageBox::Ok, QMessageBox::Ok);	
				reply->deleteLater();
				return;
			}
		}
	}
	else
	{
		ui->btcButton->setText(m_buttontext);	
		QMessageBox::critical(this, windowTitle(),
			tr("Cannot parse JSON response: ") + str,
				QMessageBox::Ok, QMessageBox::Ok);
		reply->deleteLater();
		return;
	}
	
	reply->deleteLater();
	ui->btcButton->setText(m_buttontext);	
	GUIUtil::setClipboard(m_redeemTxId);
	QMessageBox::warning(this, windowTitle(),
		tr("Escrow payment ID <b>%1</b> found in the Bitcoin blockchain but it has not been confirmed yet. Please try again later. Payment ID has been copied to your clipboard for your reference.").arg(m_redeemTxId),
			QMessageBox::Ok, QMessageBox::Ok);	
}

void ManageEscrowDialog::CheckPaymentInBTC()
{
	m_buttontext = tr("Check BTC Payment");
	ui->btcButton->setText(tr("Please Wait..."));	
	QNetworkAccessManager *nam = new QNetworkAccessManager(this);  
	connect(nam, SIGNAL(finished(QNetworkReply *)), this, SLOT(slotConfirmedFinishedCheck(QNetworkReply *)));
	QUrl url("http://btc.blockr.io/api/v1/tx/raw/" + m_redeemTxId);
	QNetworkRequest request(url);
	nam->get(request);
}
void ManageEscrowDialog::on_releaseButton_clicked()
{
    if(!walletModel) return;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		return;
    }
	if(ui->releaseButton->text() == tr("Leave Feedback"))
	{
		onLeaveFeedback();
		return;
	}
	if (releaseWarningStr.size() > 0) {
		QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Escrow Release"),
             releaseWarningStr,
             QMessageBox::Yes|QMessageBox::Cancel,
             QMessageBox::Cancel);
		if(retval == QMessageBox::Cancel)
			return;
	}
	UniValue params(UniValue::VARR);
	params.push_back(escrow.toStdString());
	string strMethod;
	if(ui->releaseButton->text() == tr("Claim Payment"))
		strMethod = string("escrowclaimrelease");
	else
	{
		strMethod = string("escrowrelease");
		params.push_back(EscrowRoleTypeToString(escrowRoleType).toStdString());
	}
	
	try {
		UniValue result = tableRPC.execute(strMethod, params);
		const UniValue& retarray = result.get_array();
		if(ui->releaseButton->text() == tr("Claim Payment"))
		{
			m_rawTx = QString::fromStdString(retarray[0].get_str());	
			if(this->m_btctxid.size() > 0)
			{
				m_buttontext = tr("Claim Payment");
				ui->releaseButton->setText(tr("Please Wait..."));
				ui->releaseButton->setEnabled(false);
				m_redeemTxId = QString::fromStdString(retarray[1].get_str());
				SendRawTxBTC();
			}
			else
			{
				if(CompleteEscrowRelease())
					ManageEscrowDialog::accept();
			}
		}
		else
		{
			const UniValue& resArray = result.get_array();
			if(resArray.size() > 1)
			{
				const UniValue& complete_value = resArray[1];
				bool bComplete = false;
				if (complete_value.isStr())
					bComplete = complete_value.get_str() == "true";
				if(!bComplete)
				{
					string hex_str = resArray[0].get_str();
					GUIUtil::setClipboard(QString::fromStdString(hex_str));
					QMessageBox::information(this, windowTitle(),
						tr("This transaction requires more signatures. Transaction hex has been copied to your clipboard for your reference. Please provide it to a signee that has not yet signed."),
							QMessageBox::Ok, QMessageBox::Ok);
					return;
				}
			}
			QMessageBox::information(this, windowTitle(),
			tr("Escrow released successfully!"),
				QMessageBox::Ok, QMessageBox::Ok);
			ManageEscrowDialog::accept();
		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error releasing escrow: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception releasing escrow"),
			QMessageBox::Ok, QMessageBox::Ok);
	}	
}
void ManageEscrowDialog::on_refundButton_clicked()
{
    if(!walletModel) return;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		return;
    }
	if (refundWarningStr.size() > 0) {
		QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Escrow Refund"),
             refundWarningStr,
             QMessageBox::Yes|QMessageBox::Cancel,
             QMessageBox::Cancel);
		if(retval == QMessageBox::Cancel)
			return;
	}
	UniValue params(UniValue::VARR);
	params.push_back(escrow.toStdString());
	string strMethod;
	if(ui->refundButton->text() == tr("Claim Refund"))
		strMethod = string("escrowclaimrefund");
	else
	{
		strMethod = string("escrowrefund");
		params.push_back(EscrowRoleTypeToString(escrowRoleType).toStdString());
	}
	
	try {
		UniValue result = tableRPC.execute(strMethod, params);
		const UniValue& retarray = result.get_array();
		if(ui->refundButton->text() == tr("Claim Refund"))
		{
			m_rawTx = QString::fromStdString(retarray[0].get_str());	
			if(this->m_btctxid.size() > 0)
			{
				m_buttontext = tr("Claim Refund");
				ui->refundButton->setText(tr("Please Wait..."));
				ui->refundButton->setEnabled(false);
				m_redeemTxId = QString::fromStdString(retarray[1].get_str());
				SendRawTxBTC();		
			}
			else
			{
				if(CompleteEscrowRefund())
					ManageEscrowDialog::accept();
			}
		}
		else
		{
			const UniValue& resArray = result.get_array();
			if(resArray.size() > 1)
			{
				const UniValue& complete_value = resArray[1];
				bool bComplete = false;
				if (complete_value.isStr())
					bComplete = complete_value.get_str() == "true";
				if(!bComplete)
				{
					string hex_str = resArray[0].get_str();
					GUIUtil::setClipboard(QString::fromStdString(hex_str));
					QMessageBox::information(this, windowTitle(),
						tr("This transaction requires more signatures. Transaction hex has been copied to your clipboard for your reference. Please provide it to a signee that has not yet signed."),
							QMessageBox::Ok, QMessageBox::Ok);
					return;
				}
			}
			QMessageBox::information(this, windowTitle(),
			tr("Escrow refunded successfully!"),
				QMessageBox::Ok, QMessageBox::Ok);
			ManageEscrowDialog::accept();
		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error refunding escrow: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception refunding escrow"),
			QMessageBox::Ok, QMessageBox::Ok);
	}
}
EscrowRoleType ManageEscrowDialog::findYourEscrowRoleFromAliases(const QString &buyer, const QString &seller, const QString &arbiter)
{
	if(isYourAlias(buyer))
		return Buyer;
	else if(isYourAlias(seller))
		return Seller;
	else if(isYourAlias(arbiter))
		return Arbiter;
	else
		return None;
    
 
}
bool ManageEscrowDialog::isYourAlias(const QString &alias)
{
	string strMethod = string("aliasinfo");
    UniValue params(UniValue::VARR); 
	UniValue result ;
	string name_str;
	int expired = 0;
	params.push_back(alias.toStdString());	
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			const UniValue& o = result.get_obj();
			const UniValue& mine_value = find_value(o, "ismine");
			if (mine_value.type() == UniValue::VBOOL)
				return mine_value.get_bool();		

		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could not refresh cert list: %1").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the cert list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}   
	return false;
}
