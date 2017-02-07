#ifndef EDITALIASDIALOG_H
#define EDITALIASDIALOG_H

#include <QDialog>

namespace Ui {
    class EditAliasDialog;
}
class AliasTableModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditAliasDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewDataAlias,
        NewAlias,
        EditDataAlias,
        EditAlias,
		TransferAlias
    };

    explicit EditAliasDialog(Mode mode, QWidget *parent = 0);
    ~EditAliasDialog();

    void setModel(WalletModel*,AliasTableModel *model);
    void loadRow(int row);
	void loadAliasDetails();

    QString getAlias() const;
    void setAlias(const QString &alias);

public Q_SLOTS:
    void accept();
	void on_okButton_clicked();
	void on_cancelButton_clicked();
	void on_addButton_clicked();
	void on_deleteButton_clicked();
	void reqSigsChanged();
	void expiryChanged(const QString& alias);
	void onCustomExpireCheckBoxChanged(bool toggled);
private:
    bool saveCurrentRow();

    Ui::EditAliasDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    AliasTableModel *model;
	WalletModel* walletModel;
    QString alias;
	QString expiredStr;
	string m_oldPassword;
	string m_oldsafesearch;
	string m_oldvalue;
	string m_oldprivatevalue;
	string m_encryptionkey;
	string m_encryptionprivkey;
	string m_oldAcceptCertTransfers;
	QListWidget m_multisigList;
};

#endif // EDITALIASDIALOG_H
