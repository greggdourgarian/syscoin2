#include "editaliasdialog.h"
#include "ui_editaliasdialog.h"

#include "aliastablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "syscoingui.h"
#include "ui_interface.h"
#include <QDataWidgetMapper>
#include <QInputDialog>
#include <QMessageBox>
#include <QSettings>
#include "rpc/server.h"
using namespace std;

extern CRPCTable tableRPC;
EditAliasDialog::EditAliasDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditAliasDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);

	ui->transferEdit->setVisible(false);
	ui->transferLabel->setVisible(false);
	ui->aliasPegDisclaimer->setText(tr("<font color='blue'>Choose an alias which has peg information. Consumers will pay conversion amounts and network fees based on this peg.</font>"));
	ui->transferDisclaimer->setText(tr("<font color='red'>Warning: Transfering your alias will transfer ownership all of your syscoin services that use this alias</font>"));
	ui->transferDisclaimer->setVisible(false);
	ui->safeSearchDisclaimer->setText(tr("<font color='blue'>Is this alias safe to search? Anything that can be considered offensive to someone should be set to <b>No</b> here. If you do create an alias that is offensive and do not set this option to <b>No</b> your alias will be banned!</font>"));
	ui->expiryEdit->clear();
	ui->expiryEdit->addItem(tr("1 Year"),"1");
	ui->expiryEdit->addItem(tr("2 Years"),"2");
	ui->expiryEdit->addItem(tr("3 Years"),"3");
	ui->expiryEdit->addItem(tr("4 Years"),"4");
	ui->expiryEdit->addItem(tr("5 Years"),"5");
	ui->expiryDisclaimer->setText(tr("<font color='blue'>Set the length of time to keep your alias from expiring. The longer you wish to keep it alive the more fees you will pay to create or update this alias. The formula for the fee is 0.2 SYS * years * years.</font>"));
    ui->privateDisclaimer->setText(tr("<font color='blue'>This is to private profile information which is encrypted and only available to you. This is useful for when sending notes to a merchant through the payment screen so you don't have to type it out everytime.</font>"));
	ui->passwordDisclaimer->setText(tr("<font color='blue'>Enter a password or passphrase that will be used to unlock this alias via webservices such as BlockMarket. Important: Do not forget or misplace this password, it is the lock to your alias.</font>"));
	ui->publicDisclaimer->setText(tr("<font color='blue'>This is public profile information that anyone on the network can see. Fill this in with things you would like others to know about you.</font>"));
	ui->reqsigsDisclaimer->setText(tr("<font color='blue'>The number of required signatures ensures that not one person can control this alias and anything service that this alias uses (certificates, messages, offers).</font>"));
	ui->acceptCertTransfersDisclaimer->setText(tr("<font color='blue'>Would you like to accept certificates transferred to this alias? Select <b>Yes</b> otherwise if you want to block others from sending certificates to this alias select <b>No</b>.</font>"));
	ui->multisigTitle->setText(tr("<font color='blue'>Set up your multisig alias here with the required number of signatures and the aliases that are capable of signing when this alias is updated. A user from this list can request an update to the alias and the other signers must sign the raw multisig transaction using the <b>Sign Multisig Tx</b> button in order for the alias to complete the update. Services that use this alias require alias updates prior to updating those services which allows all services to benefit from alias multisig technology.</font>"));
	ui->reqSigsEdit->setValidator( new QIntValidator(0, 50, this) );
	connect(ui->reqSigsEdit, SIGNAL(textChanged(QString)), this, SLOT(reqSigsChanged()));
	QString defaultPegAlias;
	QSettings settings;
	switch(mode)
    {
	case NewDataAlias:
		break;
	case NewAlias:
		setWindowTitle(tr("New Alias"));
		defaultPegAlias = settings.value("defaultPegAlias", "").toString();
		ui->aliasPegEdit->setText(defaultPegAlias);
        break;
    case EditDataAlias:
        setWindowTitle(tr("Edit Data Alias"));
		ui->aliasEdit->setEnabled(false);
        break;
    case EditAlias:
        setWindowTitle(tr("Edit Alias"));
		ui->aliasEdit->setEnabled(false);
        break;
    case TransferAlias:
        setWindowTitle(tr("Transfer Alias"));
		ui->aliasEdit->setEnabled(false);
		ui->aliasPegEdit->setEnabled(false);
		ui->aliasPegDisclaimer->setVisible(false);
		ui->nameEdit->setEnabled(false);
		ui->safeSearchEdit->setEnabled(false);
		ui->acceptCertTransfersEdit->setEnabled(false);
		ui->acceptCertTransfersDisclaimer->setVisible(false);
		ui->safeSearchDisclaimer->setVisible(false);
		ui->privateEdit->setEnabled(false);
		ui->privateDisclaimer->setVisible(false);
		ui->transferEdit->setVisible(true);
		ui->transferLabel->setVisible(true);
		ui->transferDisclaimer->setVisible(true);
		ui->addButton->setEnabled(false);
		ui->deleteButton->setEnabled(false);
		ui->passwordDisclaimer->setVisible(false);
		ui->passwordEdit->setEnabled(false);
		ui->tabWidget->setCurrentIndex(1);
        break;
    }
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

EditAliasDialog::~EditAliasDialog()
{
    delete ui;
}
void EditAliasDialog::reqSigsChanged()
{
	if(ui->multisigList->count() > 0)
	{
		ui->multisigDisclaimer->setText(tr("<font color='blue'>This is a <b>%1</b> of <b>%2</b> multisig alias (<b>%3</b> is assumed to also be a signer)</font>").arg(ui->reqSigsEdit->text()).arg(QString::number(ui->multisigList->count()+1)).arg(ui->aliasEdit->text()));
	}
}
void EditAliasDialog::loadAliasDetails()
{
	string strMethod = string("aliasinfo");
    UniValue params(UniValue::VARR); 
	params.push_back(ui->aliasEdit->text().toStdString());
	UniValue result ;
	try {
		result = tableRPC.execute(strMethod, params);
		if (result.type() == UniValue::VOBJ)
		{
			const UniValue& aliasPegValue = find_value(result.get_obj(), "alias_peg");
			ui->aliasPegEdit->setText(QString::fromStdString(aliasPegValue.get_str()));
			const UniValue& acceptTransferValue = find_value(result.get_obj(), "acceptcerttransfers");
			ui->acceptCertTransfersEdit->setCurrentIndex(ui->acceptCertTransfersEdit->findText(QString::fromStdString(acceptTransferValue.get_str())));
			const UniValue& multisigValue = find_value(result.get_obj(), "multisiginfo");
			if (multisigValue.type() == UniValue::VOBJ)
			{
				const UniValue& reqsigsValue = find_value(multisigValue.get_obj(), "reqsigs");
				int reqsigs = reqsigsValue.get_int();
				ui->reqSigsEdit->setText(QString::number(reqsigs));
				const UniValue& reqsignersValue = find_value(multisigValue.get_obj(), "reqsigners");
				if (reqsignersValue.type() == UniValue::VARR)
				{
					const UniValue& reqsignersArray = reqsignersValue.get_array();
					for(unsigned int i =0;i<reqsignersArray.size();i++)
					{
						string signer = reqsignersArray[i].get_str();
						ui->multisigList->addItem(QString::fromStdString(signer));
					}
				}
			}
		}
	}
	catch (UniValue& objError)
	{
	
	}
	catch(std::exception& e)
	{

	}  
	if(ui->multisigList->count() > 0)
	{
		ui->multisigDisclaimer->setText(tr("<font color='blue'>This is a <b>%1</b> of <b>%2</b> multisig alias (<b>%3</b> is assumed to also be a signer)</font>").arg(ui->reqSigsEdit->text()).arg(QString::number(ui->multisigList->count()+1)).arg(ui->aliasEdit->text()));
	}
}
void EditAliasDialog::on_cancelButton_clicked()
{
    reject();
}
void EditAliasDialog::on_addButton_clicked()
{
	
    bool ok;
    QString text = QInputDialog::getText(this, tr("Enter an alias"),
                                         tr("Alias:"), QLineEdit::Normal,
                                         "", &ok);
    if (ok && !text.isEmpty())
	{
        ui->multisigList->addItem(text);
	}
	if(ui->multisigList->count() > 0)
	{
		ui->multisigDisclaimer->setText(tr("<font color='blue'>This is a <b>%1</b> of <b>%2</b> multisig alias (<b>%3</b> is assumed to also be a signer)</font>").arg(ui->reqSigsEdit->text()).arg(QString::number(ui->multisigList->count()+1)).arg(ui->aliasEdit->text()));
	}
}
void EditAliasDialog::on_deleteButton_clicked()
{
    QModelIndexList selected = ui->multisigList->selectionModel()->selectedIndexes();    
	for (int i = selected.count() - 1; i > -1; --i)
		ui->multisigList->model()->removeRow(selected.at(i).row());

	if(ui->multisigList->count() > 0)
	{
		ui->multisigDisclaimer->setText(tr("<font color='blue'>This is a <b>%1</b> of <b>%2</b> multisig alias (<b>%3</b> is assumed to also be a signer)</font>").arg(ui->reqSigsEdit->text()).arg(QString::number(ui->multisigList->count()+1)).arg(ui->aliasEdit->text()));
	}
}

void EditAliasDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
}
void EditAliasDialog::setModel(WalletModel* walletModel, AliasTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    mapper->setModel(model);
	mapper->addMapping(ui->aliasEdit, AliasTableModel::Name);
    mapper->addMapping(ui->nameEdit, AliasTableModel::Value);
	mapper->addMapping(ui->privateEdit, AliasTableModel::PrivValue);
	
    
}

void EditAliasDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
	const QModelIndex tmpIndex;
	if(model)
	{
		QModelIndex indexSafeSearch= model->index(row, AliasTableModel::SafeSearch, tmpIndex);
		if(indexSafeSearch.isValid())
		{
			QString safeSearchStr = indexSafeSearch.data(AliasTableModel::SafeSearchRole).toString();
			ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText(safeSearchStr));
		}
	}
	loadAliasDetails();
}

bool EditAliasDialog::saveCurrentRow()
{
	UniValue params(UniValue::VARR);
	UniValue arraySendParams(UniValue::VARR);
	string strMethod;
    if(!model || !walletModel) return false;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		model->editStatus = AliasTableModel::WALLET_UNLOCK_FAILURE;
        return false;
    }
    switch(mode)
    {
    case NewDataAlias:
    case NewAlias:
        if (ui->aliasEdit->text().trimmed().isEmpty()) {
            ui->aliasEdit->setText("");
            QMessageBox::information(this, windowTitle(),
            tr("Empty name for Alias not allowed. Please try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
		strMethod = string("aliasnew");
		params.push_back(ui->aliasPegEdit->text().trimmed().toStdString());
        params.push_back(ui->aliasEdit->text().trimmed().toStdString());
		params.push_back(ui->passwordEdit->text().trimmed().toStdString());
		params.push_back(ui->nameEdit->toPlainText().toStdString());
		params.push_back(ui->privateEdit->toPlainText().toStdString());
		params.push_back(ui->safeSearchEdit->currentText().toStdString());
		params.push_back(ui->acceptCertTransfersEdit->currentText().toStdString());
		params.push_back(ui->expiryEdit->itemData(ui->expiryEdit->currentIndex()).toString().toStdString());
		if(ui->multisigList->count() > 0)
		{
			params.push_back(ui->reqSigsEdit->text().toStdString());
			for(int i = 0; i < ui->multisigList->count(); ++i)
			{
				QString str = ui->multisigList->item(i)->text();
				arraySendParams.push_back(str.toStdString());
			}
			params.push_back(arraySendParams);
		}

		try {
            UniValue result = tableRPC.execute(strMethod, params);
			if (result.type() != UniValue::VNULL)
			{
				alias = ui->nameEdit->toPlainText() + ui->aliasEdit->text();
					
			}
		}
		catch (UniValue& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating new Alias: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new Alias"),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case EditDataAlias:
    case EditAlias:
        if(mapper->submit())
        {
			strMethod = string("aliasupdate");
			params.push_back(ui->aliasPegEdit->text().trimmed().toStdString());
			params.push_back(ui->aliasEdit->text().toStdString());
			params.push_back(ui->nameEdit->toPlainText().toStdString());
			params.push_back(ui->privateEdit->toPlainText().toStdString());
			params.push_back(ui->safeSearchEdit->currentText().toStdString());	
			params.push_back("");
			params.push_back(ui->passwordEdit->text().toStdString());	
			params.push_back(ui->acceptCertTransfersEdit->currentText().toStdString());
			params.push_back(ui->expiryEdit->itemData(ui->expiryEdit->currentIndex()).toString().toStdString());
			if(ui->multisigList->count() > 0)
			{
				params.push_back(ui->reqSigsEdit->text().toStdString());
				for(int i = 0; i < ui->multisigList->count(); ++i)
				{
					QString str = ui->multisigList->item(i)->text();
					arraySendParams.push_back(str.toStdString());
				}
				params.push_back(arraySendParams);
			}
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
				
					alias = ui->nameEdit->toPlainText() + ui->aliasEdit->text();
						
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
				tr("Error updating Alias: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception updating Alias"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    case TransferAlias:
        if(mapper->submit())
        {
			strMethod = string("aliasupdate");
			params.push_back(ui->aliasPegEdit->text().trimmed().toStdString());
			params.push_back(ui->aliasEdit->text().toStdString());
			params.push_back(ui->nameEdit->toPlainText().toStdString());
			params.push_back(ui->privateEdit->toPlainText().toStdString());
			params.push_back(ui->safeSearchEdit->currentText().toStdString());
			params.push_back(ui->transferEdit->text().toStdString());
			params.push_back(ui->passwordEdit->text().toStdString());	
			params.push_back(ui->acceptCertTransfersEdit->currentText().toStdString());
			params.push_back(ui->expiryEdit->itemData(ui->expiryEdit->currentIndex()).toString().toStdString());
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{

					alias = ui->nameEdit->toPlainText() + ui->aliasEdit->text()+ui->transferEdit->text();
						
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
                tr("Error transferring Alias: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
                    tr("General exception transferring Alias"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    }
    return !alias.isEmpty();
}

void EditAliasDialog::accept()
{
    if(!model) return;

    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case AliasTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case AliasTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case AliasTableModel::INVALID_ALIAS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered alias \"%1\" is not a valid Syscoin Alias.").arg(ui->aliasEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case AliasTableModel::DUPLICATE_ALIAS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered alias \"%1\" is already taken.").arg(ui->aliasEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case AliasTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;

        }
        return;
    }
    QDialog::accept();
}

QString EditAliasDialog::getAlias() const
{
    return alias;
}

void EditAliasDialog::setAlias(const QString &alias)
{
    this->alias = alias;
    ui->aliasEdit->setText(alias);
}
