/*
 * Syscoin Developers 2016
 */
#include "myescrowlistpage.h"
#include "ui_myescrowlistpage.h"
#include "escrowtablemodel.h"
#include "newmessagedialog.h"
#include "manageescrowdialog.h"
#include "escrowinfodialog.h"
#include "clientmodel.h"
#include "platformstyle.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "syscoingui.h"
#include "csvmodelwriter.h"
#include "guiutil.h"
#include "ui_interface.h"
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QSettings>
#include <QMenu>
#include "rpc/server.h"
#include "stardelegate.h"
using namespace std;

extern CRPCTable tableRPC;
MyEscrowListPage::MyEscrowListPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MyEscrowListPage),
    model(0),
    optionsModel(0),
	platformStyle(platformStyle)
{
    ui->setupUi(this);
	QString theme = GUIUtil::getThemeName();  
	if (!platformStyle->getImagesOnButtons())
	{
		ui->exportButton->setIcon(QIcon());
		ui->arbiterMessageButton->setIcon(QIcon());
		ui->sellerMessageButton->setIcon(QIcon());
		ui->buyerMessageButton->setIcon(QIcon());
		ui->manageButton->setIcon(QIcon());
		ui->copyEscrow->setIcon(QIcon());
		ui->refreshButton->setIcon(QIcon());
		ui->detailButton->setIcon(QIcon());
		ui->ackButton->setIcon(QIcon());

	}
	else
	{
		ui->exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/export"));
		ui->arbiterMessageButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/outmail"));
		ui->sellerMessageButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/outmail"));
		ui->buyerMessageButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/outmail"));
		ui->manageButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/escrow1"));
		ui->copyEscrow->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/editcopy"));
		ui->refreshButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/refresh"));
		ui->detailButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/details"));
		ui->ackButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/synced"));
		
	}

    ui->labelExplanation->setText(tr("These are your registered Syscoin Escrows. Escrow operations (create, release, refund, complete) take 2-5 minutes to become active. You can choose which aliases to view related escrows using the dropdown to the right."));
	
	connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(on_detailButton_clicked()));
    // Context menu actions
    QAction *copyEscrowAction = new QAction(ui->copyEscrow->text(), this);
	QAction *copyOfferAction = new QAction(tr("&Copy Offer ID"), this);
    QAction *manageAction = new QAction(tr("Manage Escrow"), this);
	QAction *ackAction = new QAction(tr("Acknowledge Payment"), this);
	QAction *detailsAction = new QAction(tr("&Details"), this);
    QAction *buyerMessageAction = new QAction(tr("Send Msg To Buyer"), this);
	QAction *sellerMessageAction = new QAction(tr("Send Msg To Seller"), this);
	QAction *arbiterMessageAction = new QAction(tr("Send Msg To Arbiter"), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyEscrowAction);
	contextMenu->addAction(copyOfferAction);
	contextMenu->addAction(buyerMessageAction);
	contextMenu->addAction(sellerMessageAction);
	contextMenu->addAction(arbiterMessageAction);
    contextMenu->addSeparator();
	contextMenu->addAction(detailsAction);
	contextMenu->addAction(manageAction);
	contextMenu->addAction(ackAction);

    // Connect signals for context menu actions
    connect(copyEscrowAction, SIGNAL(triggered()), this, SLOT(on_copyEscrow_clicked()));
	connect(copyOfferAction, SIGNAL(triggered()), this, SLOT(on_copyOffer_clicked()));
	connect(manageAction, SIGNAL(triggered()), this, SLOT(on_manageButton_clicked()));
	connect(ackAction, SIGNAL(triggered()), this, SLOT(on_ackButton_clicked()));

	connect(buyerMessageAction, SIGNAL(triggered()), this, SLOT(on_buyerMessageButton_clicked()));
	connect(sellerMessageAction, SIGNAL(triggered()), this, SLOT(on_sellerMessageButton_clicked()));
	connect(arbiterMessageAction, SIGNAL(triggered()), this, SLOT(on_arbiterMessageButton_clicked()));
	connect(detailsAction, SIGNAL(triggered()), this, SLOT(on_detailButton_clicked()));
	

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
	connect(ui->completeCheck,SIGNAL(clicked(bool)),SLOT(onToggleShowComplete(bool)));

	connect(ui->displayListAlias,SIGNAL(currentIndexChanged(const QString&)),this,SLOT(displayListChanged(const QString&)));
	loadAliasList();

}
void MyEscrowListPage::loadAliasList()
{
	QSettings settings;
	QString oldListAlias = settings.value("defaultListAlias", "").toString();
	ui->displayListAlias->clear();
	ui->displayListAlias->addItem(tr("All"));
	
	
	UniValue aliasList(UniValue::VARR);
	appendListAliases(aliasList, true);
	for(unsigned int i = 0;i<aliasList.size();i++)
	{
		const QString& aliasName = QString::fromStdString(aliasList[i].get_str());
		ui->displayListAlias->addItem(aliasName);
	}
	int currentIndex = ui->displayListAlias->findText(oldListAlias);
	if(currentIndex >= 0)
		ui->displayListAlias->setCurrentIndex(currentIndex);
	settings.setValue("defaultListAlias", oldListAlias);
}
void MyEscrowListPage::displayListChanged(const QString& alias)
{
	QSettings settings;
	settings.setValue("defaultListAlias", alias);
	settings.sync();
}
MyEscrowListPage::~MyEscrowListPage()
{
    delete ui;
}
void MyEscrowListPage::onToggleShowComplete(bool toggled)
{
	if(!model)
		return;
	model->showComplete(toggled);
}
void MyEscrowListPage::showEvent ( QShowEvent * event )
{
    if(!walletModel) return;

}
void MyEscrowListPage::setModel(WalletModel *walletModel, EscrowTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;
    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
  
	// Receive filter
	proxyModel->setFilterRole(EscrowTableModel::TypeRole);

	ui->tableView->setModel(proxyModel);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);

    // Set column widths
    ui->tableView->setColumnWidth(0, 50); //escrow id
    ui->tableView->setColumnWidth(1, 50); //time
    ui->tableView->setColumnWidth(2, 150); //seller
    ui->tableView->setColumnWidth(3, 150); //arbiter
    ui->tableView->setColumnWidth(4, 150); //buyer
    ui->tableView->setColumnWidth(5, 80); //offer
	ui->tableView->setColumnWidth(6, 250); //offer title
	ui->tableView->setColumnWidth(7, 80); //total
	ui->tableView->setColumnWidth(8, 150); //rating
    ui->tableView->setColumnWidth(9, 50); //status
	ui->tableView->setItemDelegateForColumn(8, new StarDelegate);

    ui->tableView->horizontalHeader()->setStretchLastSection(true);

    // Select row for newly created escrow
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(selectNewEscrow(QModelIndex,int,int)));
}

void MyEscrowListPage::setOptionsModel(ClientModel* clientmodel, OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
	this->clientModel = clientmodel;
}

void MyEscrowListPage::on_copyEscrow_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, EscrowTableModel::Escrow);
}
void MyEscrowListPage::on_ackButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString escrow = selection.at(0).data(EscrowTableModel::EscrowRole).toString();
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Escrow Acknowledgement"),
         tr("Warning: You are about to acknowledge this payment from the buyer. If you are shipping an item, please communicate a tracking number to the buyer via a Syscoin message.") + "<br><br>" + tr("Are you sure you wish to acknowledge this payment?"),
         QMessageBox::Yes|QMessageBox::Cancel,
         QMessageBox::Cancel);
    if(retval == QMessageBox::Yes)
    {
		UniValue params(UniValue::VARR);
		string strMethod = string("escrowacknowledge");
		params.push_back(escrow.toStdString());

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
				}
			}
		}
		catch (UniValue& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error acknowledging escrow payment: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception acknowledging escrow payment"),
				QMessageBox::Ok, QMessageBox::Ok);
		}
	}     
}
void MyEscrowListPage::on_copyOffer_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, EscrowTableModel::Offer);
}
void MyEscrowListPage::on_manageButton_clicked()
{
 	if(!model || !walletModel)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString escrow = selection.at(0).data(EscrowTableModel::EscrowRole).toString();
	ManageEscrowDialog dlg(walletModel, escrow);   
	dlg.exec();
}
void MyEscrowListPage::on_buyerMessageButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString buyer = selection.at(0).data(EscrowTableModel::BuyerRole).toString();
	// send message to seller
	NewMessageDialog dlg(NewMessageDialog::NewMessage, buyer);   
	dlg.exec();
}
void MyEscrowListPage::on_sellerMessageButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString sellerAlias = selection.at(0).data(EscrowTableModel::SellerRole).toString();
	// send message to seller
	NewMessageDialog dlg(NewMessageDialog::NewMessage, sellerAlias);   
	dlg.exec();
}
void MyEscrowListPage::on_arbiterMessageButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString arbAlias = selection.at(0).data(EscrowTableModel::ArbiterRole).toString();
	// send message to arbiter
	NewMessageDialog dlg(NewMessageDialog::NewMessage, arbAlias);   
	dlg.exec();
}
void MyEscrowListPage::on_refreshButton_clicked()
{
    if(!model)
        return;
	loadAliasList();
    model->refreshEscrowTable();
}

void MyEscrowListPage::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Escrow Data"), QString(),
            tr("Comma separated file (*.csv)"), NULL);

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Escrow", EscrowTableModel::Escrow, Qt::EditRole);
	writer.addColumn("Time", EscrowTableModel::Time, Qt::EditRole);
    writer.addColumn("Arbiter", EscrowTableModel::Arbiter, Qt::EditRole);
	writer.addColumn("Seller", EscrowTableModel::Seller, Qt::EditRole);
	writer.addColumn("Offer", EscrowTableModel::Offer, Qt::EditRole);
	writer.addColumn("OfferTitle", EscrowTableModel::OfferTitle, Qt::EditRole);
	writer.addColumn("Total", EscrowTableModel::Total, Qt::EditRole);
	writer.addColumn("Rating", EscrowTableModel::Rating, EscrowTableModel::RatingRole);
	writer.addColumn("RatingCount", EscrowTableModel::Rating, EscrowTableModel::RatingCountRole);
	writer.addColumn("Status", EscrowTableModel::Status, Qt::EditRole);
    if(!writer.write()) {
        Q_EMIT message(tr("Exporting Failed"), tr("Could not export to file %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
    }
    else {
        Q_EMIT message(tr("Exporting Successful"), tr("Export successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void MyEscrowListPage::on_detailButton_clicked()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        EscrowInfoDialog dlg(platformStyle, selection.at(0));
        dlg.exec();
    }
}
void MyEscrowListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void MyEscrowListPage::selectNewEscrow(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, EscrowTableModel::Escrow, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newEscrowToSelect))
    {
        // Select row of newly created escrow, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newEscrowToSelect.clear();
    }
}
