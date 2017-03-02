/*
 * Syscoin Developers 2015
 */
#include "certview.h"
#include "syscoingui.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "mycertlistpage.h"
#include "certtablemodel.h"
#include "ui_interface.h"

#include <QAction>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QPushButton>

CertView::CertView(const PlatformStyle *platformStyle, QStackedWidget *parent):
    clientModel(0),
    walletModel(0)
{
	tabWidget = new QTabWidget();
    myCertListPage = new MyCertListPage(platformStyle);
	QString theme = GUIUtil::getThemeName();
	tabWidget->addTab(myCertListPage, tr("My Certificates"));
	tabWidget->setTabIcon(0, platformStyle->SingleColorIcon(":/icons/" + theme + "/cert"));
	parent->addWidget(tabWidget);

}

CertView::~CertView()
{
}

void CertView::setSyscoinGUI(SyscoinGUI *gui)
{
    this->gui = gui;
}

void CertView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if (clientModel)
    {
       
		myCertListPage->setOptionsModel(clientModel,clientModel->getOptionsModel());

    }
}

void CertView::setWalletModel(WalletModel *walletModel)
{

    this->walletModel = walletModel;
    if (walletModel)
    {

		myCertListPage->setModel(walletModel, walletModel->getCertTableModelMine());

    }
}


void CertView::gotoCertListPage()
{
	tabWidget->setCurrentWidget(myCertListPage);
}

