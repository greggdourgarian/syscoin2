/*
 * Syscoin Developers 2016
 */
#include "aliasview.h"
#include "syscoingui.h"

#include "platformstyle.h"
#include "guiutil.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "myaliaslistpage.h"
#include "aliastablemodel.h"
#include "ui_interface.h"

#include <QAction>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QPushButton>

AliasView::AliasView(const PlatformStyle *platformStyle, QStackedWidget *parent):
    clientModel(0),
    walletModel(0)
{
	tabWidget = new QTabWidget();
    myAliasListPage = new MyAliasListPage(platformStyle);
	QString theme = GUIUtil::getThemeName();
	tabWidget->addTab(myAliasListPage, tr("My Aliases"));
	tabWidget->setTabIcon(0, platformStyle->SingleColorIcon(":/icons/" + theme + "/alias"));
	parent->addWidget(tabWidget);

}

AliasView::~AliasView()
{
}

void AliasView::setSyscoinGUI(SyscoinGUI *gui)
{
    this->gui = gui;
}

void AliasView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if (clientModel)
    {
		myAliasListPage->setOptionsModel(clientModel,clientModel->getOptionsModel());
    }
}

void AliasView::setWalletModel(WalletModel *walletModel)
{

    this->walletModel = walletModel;
    if (walletModel)
    {

		myAliasListPage->setModel(walletModel, walletModel->getAliasTableModelMine());

    }
}


void AliasView::gotoAliasListPage()
{
	tabWidget->setCurrentWidget(myAliasListPage);
}
