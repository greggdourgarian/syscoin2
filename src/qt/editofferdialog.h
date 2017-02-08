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

    explicit EditOfferDialog(Mode mode, const QString &offer="", const QString &cert="", const QString &alias="", const QString &cat="", QWidget *parent = 0);
    ~EditOfferDialog();

    void setModel(WalletModel*,OfferTableModel *model);
    void loadRow(int row);
    void addParentItem(QStandardItemModel * model, const QString& text, const QVariant& data );
    void addChildItem( QStandardItemModel * model, const QString& text, const QVariant& data );
	void setOfferNotSafeBecauseOfAlias(const QString &alias);
	void resetSafeSearch();
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
	void loadCategories();
    Ui::EditOfferDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    OfferTableModel *model;
	WalletModel* walletModel;
    QString offer;
	QString cert;
	QString alias;
	QString commission;
	bool overrideSafeSearch;
	QString expiredStr;
	QString m_oldcategory;
	QString m_oldtitle;
	QString m_oldqty;
	QString m_oldprice;
	QString m_olddescription;
	QString m_oldcurrency;
	QString m_oldprivate);
	QString m_oldcert;
	QString m_oldgeolocation;
	QString m_oldsafesearch;
	QString m_oldcommission;
	QString m_oldpaymentoptions;
};

#endif // EDITOFFERDIALOG_H
