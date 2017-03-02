/*
 * Syscoin Developers 2016
 */
#include "escrowview.h"
#include "syscoingui.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "myescrowlistpage.h"
#include "escrowtablemodel.h"
#include "ui_interface.h"

#include <QAction>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QPushButton>

EscrowView::EscrowView(const PlatformStyle *platformStyle, QStackedWidget *parent):
    clientModel(0),
    walletModel(0)
{
	tabWidget = new QTabWidget();
    myEscrowListPage = new MyEscrowListPage(platformStyle);
	QString theme = GUIUtil::getThemeName();

	tabWidget->addTab(myEscrowListPage, tr("My Escrows"));
	tabWidget->setTabIcon(0, QIcon(":/icons/" + theme + "/escrow"));

	parent->addWidget(tabWidget);

}

EscrowView::~EscrowView()
{
}

void EscrowView::setSyscoinGUI(SyscoinGUI *gui)
{
    this->gui = gui;
}

void EscrowView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if (clientModel)
    {    
		myEscrowListPage->setOptionsModel(clientModel,clientModel->getOptionsModel());
    }
}

void EscrowView::setWalletModel(WalletModel *walletModel)
{

    this->walletModel = walletModel;
    if (walletModel)
    {
		myEscrowListPage->setModel(walletModel, walletModel->getEscrowTableModelMine());

    }
}


void EscrowView::gotoEscrowListPage()
{
	tabWidget->setCurrentWidget(myEscrowListPage);
}
