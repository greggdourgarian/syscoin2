#ifndef EDITOFFERDIALOG_H
#define EDITOFFERDIALOG_H

#include <QDialog>

namespace Ui {
    class EditOfferDialog;
}
class OfferTableModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
class QString;
class QStandardItemModel;
QT_END_NAMESPACE

/** Dialog for editing an offer
 */
class EditOfferDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewOffer,
        EditOffer,
		NewCertOffer
    };

    explicit EditOfferDialog(Mode mode, const QString &offer="", const QString &cert="", const QString &alias="", QWidget *parent = 0);
    ~EditOfferDialog();

    void setModel(WalletModel*,OfferTableModel *model);
    void loadRow(int row);
    QString getOffer() const;
    void setOffer(const QString &offer);

public Q_SLOTS:
    void accept();
	void aliasChanged(const QString& text);
	void certChanged(int);
	void on_aliasPegEdit_editingFinished();
	void on_okButton_clicked();
	void on_cancelButton_clicked();
private:
	bool isLinkedOffer(const QString& offerGUID);
    bool saveCurrentRow();
	void loadCerts(const QString& alias);
	void loadAliases();
    Ui::EditOfferDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    OfferTableModel *model;
	WalletModel* walletModel;
    QString offer;
	QString cert;
	QString alias;
	QString commission;
	QString expiredStr;
	QString m_oldqty;
	QString m_oldprice;
	QString m_olddetails;
	QString m_oldcurrency;
	QString m_oldprivate;
	QString m_oldcert;
	QString m_oldcommission;
	QString m_oldpaymentoptions;
};

#endif // EDITOFFERDIALOG_H
