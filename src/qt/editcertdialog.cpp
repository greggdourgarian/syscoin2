#include "editcertdialog.h"
#include "ui_editcertdialog.h"
#include "cert.h"
#include "alias.h"
#include "wallet/crypter.h"
#include "random.h"
#include "certtablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "syscoingui.h"
#include "ui_interface.h"
#include <QDataWidgetMapper>
#include <QMessageBox>
#include "rpc/server.h"
#include <QStandardItemModel>
#include "qcomboboxdelegate.h"
#include <boost/algorithm/string.hpp>
#include <QSettings>
using namespace std;

extern CRPCTable tableRPC;
extern bool getCategoryList(vector<string>& categoryList);
EditCertDialog::EditCertDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditCertDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);
	ui->certLabel->setVisible(true);
	ui->certEdit->setVisible(true);
	ui->certEdit->setEnabled(false);
	ui->certDataEdit->setVisible(true);
	ui->certDataEdit->setEnabled(true);
	ui->certDataLabel->setVisible(true);
	ui->certDataEdit->setStyleSheet("color: rgb(0, 0, 0); background-color: rgb(255, 255, 255)");
	ui->transferLabel->setVisible(false);
	ui->transferEdit->setVisible(false);
	ui->transferDisclaimer->setText(QString("<font color='blue'>") + tr("Enter the alias of the recipient of this certificate") + QString("</font>"));
    ui->transferDisclaimer->setVisible(false);
	ui->viewOnlyDisclaimer->setText(QString("<font color='blue'>") + tr("Select Yes if you do not want this certificate to be editable/transferable by the recipient") + QString("</font>"));
	ui->viewOnlyBox->setVisible(false);
	ui->viewOnlyLabel->setVisible(false);
	ui->viewOnlyDisclaimer->setVisible(false);
	loadAliases();
	connect(ui->aliasEdit,SIGNAL(currentIndexChanged(const QString&)),this,SLOT(aliasChanged(const QString&)));
	
	QSettings settings;
	QString defaultCertAlias;
	int aliasIndex;
	switch(mode)
    {
    case NewCert:
		ui->certLabel->setVisible(false);
		ui->certEdit->setVisible(false);
		
		defaultCertAlias = settings.value("defaultCertAlias", "").toString();
		aliasIndex = ui->aliasEdit->findText(defaultCertAlias);
		if(aliasIndex >= 0)
			ui->aliasEdit->setCurrentIndex(aliasIndex);
        setWindowTitle(tr("New Cert"));
        break;
    case EditCert:
        setWindowTitle(tr("Edit Cert"));
		
        break;
    case TransferCert:
        setWindowTitle(tr("Transfer Cert"));
		ui->certDataEdit->setVisible(false);
		ui->certDataEdit->setEnabled(false);
		ui->certDataLabel->setVisible(false);
		ui->transferLabel->setVisible(true);
		ui->transferEdit->setVisible(true);
		ui->transferDisclaimer->setVisible(true);
		ui->aliasDisclaimer->setVisible(false);
		ui->aliasEdit->setEnabled(false);
		ui->viewOnlyBox->setVisible(true);
		ui->viewOnlyLabel->setVisible(true);
		ui->viewOnlyDisclaimer->setVisible(true);
        break;
    }
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
	aliasChanged(ui->aliasEdit->currentText());
	
}
	
void EditCertDialog::aliasChanged(const QString& alias)
{
	string strMethod = string("aliasinfo");
    UniValue params(UniValue::VARR); 
	params.push_back(alias.toStdString());
	UniValue result ;
	string name_str;
	bool expired = false;

	int safetyLevel;
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			name_str = "";
		
			expired = safetyLevel = 0;
			const UniValue& o = result.get_obj();
			name_str = "";
		
			expired = safetyLevel = 0;

			const UniValue& name_value = find_value(o, "name");
			if (name_value.type() == UniValue::VSTR)
				name_str = name_value.get_str();		
			const UniValue& expired_value = find_value(o, "expired");
			if (expired_value.type() == UniValue::VBOOL)
				expired = expired_value.get_bool();
			const UniValue& sl_value = find_value(o, "safetylevel");
			if (sl_value.type() == UniValue::VNUM)
				safetyLevel = sl_value.get_int();
			const UniValue& encryption_value = find_value(o, "encryption_publickey");
			if (encryption_value.type() == UniValue::VSTR)
				m_encryptionkey = QString::fromStdString(encryption_value.get_str());
			if(expired)
			{
				ui->aliasDisclaimer->setText(QString("<font color='red'>") + tr("This alias has expired, please choose another one") + QString("</font>"));				
			}
			else
				ui->aliasDisclaimer->setText(QString("<font color='blue'>") + tr("Select an alias to own this certificate") + QString("</font>"));
		}
		else
		{
		
			ui->aliasDisclaimer->setText(QString("<font color='blue'>") + tr("Select an alias to own this certificate") + QString("</font>"));
		}
	}
	catch (UniValue& objError)
	{
		ui->aliasDisclaimer->setText(QString("<font color='blue'>") + tr("Select an alias to own this certificate") + QString("</font>"));
	}
	catch(std::exception& e)
	{
		ui->aliasDisclaimer->setText(QString("<font color='blue'>") + tr("Select an alias to own this certificate") + QString("</font>"));
	}  
}
void EditCertDialog::loadAliases()
{
	ui->aliasEdit->clear();
	string strMethod = string("aliaslist");
    UniValue params(UniValue::VARR); 
	UniValue result ;
	string name_str;
	bool expired = false;
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VARR)
		{
			name_str = "";
			expired = false;


	
			const UniValue &arr = result.get_array();
		    for (unsigned int idx = 0; idx < arr.size(); idx++) {
			    const UniValue& input = arr[idx];
				if (input.type() != UniValue::VOBJ)
					continue;
				const UniValue& o = input.get_obj();
				name_str = "";
				expired = 0;
		
				const UniValue& name_value = find_value(o, "name");
				if (name_value.type() == UniValue::VSTR)
					name_str = name_value.get_str();		
				const UniValue& expired_value = find_value(o, "expired");
				if (expired_value.type() == UniValue::VBOOL)
					expired = expired_value.get_bool();
				if(expired == false)
				{
					QString name = QString::fromStdString(name_str);
					ui->aliasEdit->addItem(name);					
				}				
			}
		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could not refresh alias list: ") + QString::fromStdString(strError),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the alias list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}         
 
}
EditCertDialog::~EditCertDialog()
{
    delete ui;
}

void EditCertDialog::setModel(WalletModel* walletModel, CertTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    mapper->setModel(model);
	mapper->addMapping(ui->certEdit, CertTableModel::Name);
	mapper->addMapping(ui->certDataEdit, CertTableModel::Data);
	mapper->addMapping(ui->certPubDataEdit, CertTableModel::PubData);
    
}

void EditCertDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
	const QModelIndex tmpIndex;
	if(model)
	{
		QModelIndex indexAlias = model->index(row, CertTableModel::Alias, tmpIndex);
		QModelIndex indexExpired = model->index(row, CertTableModel::Expired, tmpIndex);
		if(indexExpired.isValid())
		{
			expiredStr = indexExpired.data(CertTableModel::ExpiredRole).toString();
		}
		if(indexAlias.isValid())
		{
			QString aliasStr = indexAlias.data(CertTableModel::AliasRole).toString();
			int indexInComboBox = ui->aliasEdit->findText(aliasStr);
			if(indexInComboBox < 0)
				indexInComboBox = 0;
			ui->aliasEdit->setCurrentIndex(indexInComboBox);
		}
	}
	m_oldprivatevalue = ui->certDataEdit->toPlainText();
	m_oldpubdata = ui->certPubDataEdit->toPlainText();
}

bool EditCertDialog::saveCurrentRow()
{
	string privdata = "";
	string pubData = "";
	string strCipherEncryptionPrivateKey = "";
	string strCipherEncryptionPublicKey = "";
	string strCipherPrivateData = "";
    if(!model || !walletModel) return false;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		model->editStatus = CertTableModel::WALLET_UNLOCK_FAILURE;
        return false;
    }
	if(expiredStr == "Expired")
	{
        QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Certificate Renewal"),
                 tr("Warning: This certificate is already expired!") + "<br><br>" + tr("Do you want to create a new one with the same information?"),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
        if(retval == QMessageBox::Cancel)
			return false;
		mode = NewCert;
	}
	UniValue params(UniValue::VARR);
	string strMethod;
	QVariant currentCategory;
	CKey privEncryptionKey;
	CPubKey pubEncryptionKey;
	vector<unsigned char> vchPrivEncryptionKey, vchPubEncryptionKey;
    switch(mode)
    {
    case NewCert:
		privEncryptionKey.MakeNewKey(true);
		pubEncryptionKey = privEncryptionKey.GetPubKey();
		vchPrivEncryptionKey = vector<unsigned char>(privEncryptionKey.begin(), privEncryptionKey.end());
		vchPubEncryptionKey = vector<unsigned char>(pubEncryptionKey.begin(), pubEncryptionKey.end());
		
		privdata = ui->certDataEdit->toPlainText().toStdString();
		if(privdata != m_oldprivatevalue.toStdString())
		{
			if(!EncryptMessage(vchPubEncryptionKey, privdata, strCipherPrivateData))
			{
					QMessageBox::critical(this, windowTitle(),
						tr("Could not encrypt private certificate data!"),
						QMessageBox::Ok, QMessageBox::Ok);
					return false;
			}
			if(!EncryptMessage(ParseHex(m_encryptionkey.toStdString()), stringFromVch(vchPrivEncryptionKey), strCipherEncryptionPrivateKey))
			{
					QMessageBox::critical(this, windowTitle(),
						tr("Could not encrypt certificate private encryption key!"),
						QMessageBox::Ok, QMessageBox::Ok);
					return false;
			}
		}

		if(strCipherPrivateData.empty())
			strCipherPrivateData = "\"\"";
		else
			strCipherPrivateData = HexStr(vchFromString(strCipherPrivateData));
		if(strCipherEncryptionPrivateKey.empty())
		{
			strCipherEncryptionPrivateKey = "\"\"";
			strCipherEncryptionPublicKey = "\"\"";
		}
		else
		{
			strCipherEncryptionPrivateKey = HexStr(vchFromString(strCipherEncryptionPrivateKey));
			strCipherEncryptionPublicKey = HexStr(vchPubEncryptionKey);
		}
		strMethod = string("certnew");
		params.push_back(ui->aliasEdit->currentText().toStdString());
		params.push_back(ui->certPubDataEdit->toPlainText().toStdString());
		params.push_back(strCipherPrivateData);
		params.push_back(strCipherEncryptionPublicKey);
		params.push_back(strCipherEncryptionPrivateKey);
		try {
            UniValue result = tableRPC.execute(strMethod, params);
			if (result.type() != UniValue::VNULL)
			{
				cert = ui->aliasEdit->text();
					
			}
			const UniValue& resArray = result.get_array();
			if(resArray.size() > 2)
			{
				const UniValue& complete_value = resArray[2];
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
		}
		catch (UniValue& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating new Cert: ") + QString::fromStdString(strError),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new Cert"),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case EditCert:
        if(mapper->submit())
        {
			privdata = ui->certDataEdit->toPlainText().toStdString();
			if(privdata != m_oldprivatevalue.toStdString())
			{
				if(!EncryptMessage(vchPubEncryptionKey, privdata, strCipherPrivateData))
				{
						QMessageBox::critical(this, windowTitle(),
							tr("Could not encrypt private certificate data!"),
							QMessageBox::Ok, QMessageBox::Ok);
						return false;
				}
				if(!EncryptMessage(ParseHex(m_encryptionkey.toStdString()), stringFromVch(vchPrivEncryptionKey), strCipherEncryptionPrivateKey))
				{
						QMessageBox::critical(this, windowTitle(),
							tr("Could not encrypt certificate private encryption key!"),
							QMessageBox::Ok, QMessageBox::Ok);
						return false;
				}
			}
			if(strCipherPrivateData.empty())
				strCipherPrivateData = "\"\"";
			else
				strCipherPrivateData = HexStr(vchFromString(strCipherPrivateData));
			if(strCipherEncryptionPrivateKey.empty())
			{
				strCipherEncryptionPrivateKey = "\"\"";
				strCipherEncryptionPublicKey = "\"\"";
			}
			else
			{
				strCipherEncryptionPrivateKey = HexStr(vchFromString(strCipherEncryptionPrivateKey));
				strCipherEncryptionPublicKey = HexStr(vchPubEncryptionKey);
			}
			pubData = "\"\"";
			if(ui->certPubDataEdit->toPlainText() != m_oldpubdata)
				pubData = ui->certPubDataEdit->toPlainText().toStdString();


			strMethod = string("certupdate");
			params.push_back(ui->certEdit->text().toStdString());
			params.push_back(pubData);
			params.push_back(strCipherPrivateData);
			params.push_back(strCipherEncryptionPublicKey);
			params.push_back(strCipherEncryptionPrivateKey);
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
					cert = ui->nameEdit->text() + ui->certEdit->text();

				}
				const UniValue& resArray = result.get_array();
				if(resArray.size() > 1)
				{
					bool bComplete = false;
					const UniValue& complete_value = resArray[1];
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
			}
			catch (UniValue& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
				tr("Error updating Cert: ") + QString::fromStdString(strError),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception updating Cert"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    case TransferCert:
        if(mapper->submit())
        {
			privdata = ui->certDataEdit->toPlainText().toStdString();
			if(privdata != m_oldprivatevalue.toStdString())
			{
				if(!EncryptMessage(vchPubEncryptionKey, privdata, strCipherPrivateData))
				{
						QMessageBox::critical(this, windowTitle(),
							tr("Could not encrypt private certificate data!"),
							QMessageBox::Ok, QMessageBox::Ok);
						return false;
				}
				if(!EncryptMessage(ParseHex(m_encryptionkey.toStdString()), stringFromVch(vchPrivEncryptionKey), strCipherEncryptionPrivateKey))
				{
						QMessageBox::critical(this, windowTitle(),
							tr("Could not encrypt certificate private encryption key!"),
							QMessageBox::Ok, QMessageBox::Ok);
						return false;
				}
			}
			if(strCipherPrivateData.empty())
				strCipherPrivateData = "\"\"";
			else
				strCipherPrivateData = HexStr(vchFromString(strCipherPrivateData));
			if(strCipherEncryptionPrivateKey.empty())
			{
				strCipherEncryptionPrivateKey = "\"\"";
				strCipherEncryptionPublicKey = "\"\"";
			}
			else
			{
				strCipherEncryptionPrivateKey = HexStr(vchFromString(strCipherEncryptionPrivateKey));
				strCipherEncryptionPublicKey = HexStr(vchPubEncryptionKey);
			}
			pubData = "\"\"";
			if(ui->certPubDataEdit->toPlainText() != m_oldpubdata)
				pubData = ui->certPubDataEdit->toPlainText().toStdString();
			strMethod = string("certtransfer");
			params.push_back(ui->certEdit->text().toStdString());
			params.push_back(ui->transferEdit->text().toStdString());
			params.push_back(pubData);
			params.push_back(strCipherPrivateData);
			params.push_back(strCipherEncryptionPublicKey);
			params.push_back(strCipherEncryptionPrivateKey);
			params.push_back(ui->viewOnlyBox->currentText().toStdString());
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
					cert = ui->certEdit->text()+ui->transferEdit->text();

				}
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
			}
			catch (UniValue& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
                tr("Error transferring Cert: ") + QString::fromStdString(strError),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
                    tr("General exception transferring Cert"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    }
    return !cert.isEmpty();
}

void EditCertDialog::accept()
{
    if(!model) return;

    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case CertTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case CertTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case CertTableModel::INVALID_CERT:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered cert is not a valid Syscoin cert."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case CertTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;

        }
        return;
    }
    QDialog::accept();
}

QString EditCertDialog::getCert() const
{
    return cert;
}

void EditCertDialog::setCert(const QString &cert)
{
    this->cert = cert;
    ui->certEdit->setText(cert);
}
