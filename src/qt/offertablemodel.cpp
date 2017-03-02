#include "offertablemodel.h"

#include "guiutil.h"
#include "walletmodel.h"

#include "wallet/wallet.h"
#include "base58.h"

#include <QFont>
#include <QSettings>
#include "rpc/server.h"
using namespace std;


const QString OfferTableModel::Offer = "O";


extern CRPCTable tableRPC;
struct OfferTableEntry
{
    enum Type {
        Offer
    };

    Type type;
	QString cert;
	QString details;
    QString offer;
	QString price;
	QString currency;
	QString qty;
	QString expired;
	QString private_str;
	QString alias;
	QString aliasRating;
	QString paymentoptions;
	QString alias_peg;
    OfferTableEntry() {}
    OfferTableEntry(Type type,const QString &cert,const QString &offer, const QString &details, const QString &price, const QString &currency,const QString &qty,const QString &expired, const QString &private_str,const QString &alias,const QString &aliasRating, const QString &paymentoptions, const QString &alias_peg):
        type(type), cert(cert), offer(offer), details(details), price(price), currency(currency),qty(qty), expired(expired),private_str(private_str), alias(alias), aliasRating(aliasRating), paymentoptions(paymentoptions),alias_peg(alias_peg) {}
};
struct OfferTableEntryLessThan
{
    bool operator()(const OfferTableEntry &a, const OfferTableEntry &b) const
    {
        return a.offer < b.offer;
    }
    bool operator()(const OfferTableEntry &a, const QString &b) const
    {
        return a.offer < b;
    }
    bool operator()(const QString &a, const OfferTableEntry &b) const
    {
        return a < b.offer;
    }
};

// Private implementation
class OfferTablePriv
{
public:
    CWallet *wallet;
    QList<OfferTableEntry> cachedOfferTable;
    OfferTableModel *parent;
	bool showSoldOut;
	bool showDigitalOffers;
    OfferTablePriv(CWallet *wallet, OfferTableModel *parent):
        wallet(wallet), parent(parent), showSoldOut(false), showDigitalOffers(false)  {}

    void refreshOfferTable(OfferModelType type)
    {
        cachedOfferTable.clear();
        {
			string strMethod = string("offerlist");
	        UniValue params(UniValue::VARR); 
			UniValue listAliases(UniValue::VARR);
			appendListAliases(listAliases);
			params.push_back(listAliases);
			
			UniValue result ;
			string name_str;
		
			string cert_str;
			string desc_str;
		
			string price_str;
			string currency_str;
			string qty_str;
			string expired_str;
			string private_str;
			string alias_str;
			string paymentoptions_str;
			string alias_peg_str;

			string aliasRating_str;
			bool expired = false;

			

			try {
				result = tableRPC.execute(strMethod, params);

				if (result.type() == UniValue::VARR)
				{
					name_str = "";
					cert_str = "";

					desc_str = "";

					expired = false;
					aliasRating_str = "";


			
					const UniValue &arr = result.get_array();
					for (unsigned int idx = 0; idx < arr.size(); idx++) {
						const UniValue& input = arr[idx];
						if (input.type() != UniValue::VOBJ)
							continue;
						const UniValue& o = input.get_obj();
						name_str = "";
						private_str = "";
						alias_str = "";
						paymentoptions_str = "";
						alias_peg_str = "";

						expired = false;
						aliasRating_str = "";

				
						const UniValue& name_value = find_value(o, "offer");
						if (name_value.type() == UniValue::VSTR)
							name_str = name_value.get_str();
						const UniValue& cert_value = find_value(o, "cert");
						if (cert_value.type() == UniValue::VSTR)
							cert_str = cert_value.get_str();
						if(showDigitalOffers && cert_str.size() <= 0)
							continue;
						const UniValue& desc_value = find_value(o, "details");
						if (desc_value.type() == UniValue::VSTR)
							desc_str = desc_value.get_str();

						const UniValue& price_value = find_value(o, "price");
						if (price_value.type() == UniValue::VSTR)
							price_str = price_value.get_str();
						const UniValue& currency_value = find_value(o, "currency");
						if (currency_value.type() == UniValue::VSTR)
							currency_str = currency_value.get_str();
						const UniValue& qty_value = find_value(o, "quantity");
						if (qty_value.type() == UniValue::VSTR)
							qty_str = qty_value.get_str();
						const UniValue& expired_value = find_value(o, "expired");
						if (expired_value.type() == UniValue::VBOOL)
							expired = expired_value.get_bool();
						if((qty_str == "0" || expired ) && !showSoldOut)
							continue;
						const UniValue& private_value = find_value(o, "private");
						if (private_value.type() == UniValue::VSTR)
							private_str = private_value.get_str();
						const UniValue& alias_value = find_value(o, "alias");
						if (alias_value.type() == UniValue::VSTR)
							alias_str = alias_value.get_str();
						const UniValue& aliasRating_value = find_value(o, "alias_rating_display");
						if (aliasRating_value.type() == UniValue::VSTR)
							aliasRating_str = aliasRating_value.get_str();
						const UniValue& paymentoptions_value = find_value(o, "paymentoptions_display");
						if (paymentoptions_value.type() == UniValue::VSTR)
							paymentoptions_str = paymentoptions_value.get_str();
						const UniValue& alias_peg_value = find_value(o, "alias_peg");
						if (alias_peg_value.type() == UniValue::VSTR)
							alias_peg_str = alias_peg_value.get_str();
						
						if(expired == 1)
						{
							expired_str = "Expired";
						}
						else
						{
							expired_str = "Valid";
						}

						updateEntry( QString::fromStdString(name_str), QString::fromStdString(cert_str), QString::fromStdString(desc_str), QString::fromStdString(price_str), QString::fromStdString(currency_str), QString::fromStdString(qty_str), QString::fromStdString(expired_str), QString::fromStdString(private_str),QString::fromStdString(alias_str), QString::fromStdString(aliasRating_str), QString::fromStdString(paymentoptions_str), QString::fromStdString(alias_peg_str), type, CT_NEW); 
					}
				}
   			}
			catch (UniValue& objError)
			{
				return;
			}
			catch(std::exception& e)
			{
				return;
			}         
         }
    }

    void updateEntry(const QString &offer, const QString &cert, const QString &details, const QString &price, const QString &currency,const QString &qty,const QString &expired, const QString &private_str, const QString &alias, const QString &aliasRating, const QString &paymentOptions, const QString &alias_peg, OfferModelType type, int status)
    {
		if(!parent || parent->modelType != type)
		{
			return;
		}
        // Find offer / value in model
        QList<OfferTableEntry>::iterator lower = qLowerBound(
            cachedOfferTable.begin(), cachedOfferTable.end(), offer, OfferTableEntryLessThan());
        QList<OfferTableEntry>::iterator upper = qUpperBound(
            cachedOfferTable.begin(), cachedOfferTable.end(), offer, OfferTableEntryLessThan());
        int lowerIndex = (lower - cachedOfferTable.begin());
        int upperIndex = (upper - cachedOfferTable.begin());
        bool inModel = (lower != upper);
        OfferTableEntry::Type newEntryType = OfferTableEntry::Offer;

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedOfferTable.insert(lowerIndex, OfferTableEntry(newEntryType, cert, offer, details, price, currency, qty, expired, private_str, alias, aliasRating, paymentOptions, alias_peg));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                break;
            }
            lower->type = newEntryType;
			lower->cert = cert;
			lower->details = details;
			lower->price = price;
			lower->currency = currency;
			lower->qty = qty;
			lower->expired = expired;
			lower->private_str = private_str;
			lower->alias = alias;
			lower->aliasRating = aliasRating;
			lower->paymentoptions = paymentOptions;
			lower->alias_peg = alias_peg;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedOfferTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedOfferTable.size();
    }

    OfferTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedOfferTable.size())
        {
            return &cachedOfferTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

OfferTableModel::OfferTableModel(CWallet *wallet, WalletModel *parent,  OfferModelType type) :
    QAbstractTableModel(parent),walletModel(parent),wallet(wallet),priv(0), modelType(type)
{
    columns << tr("Offer") << tr("Certificate") << tr("Details") << tr("Price") << tr("Currency") << tr("Qty") << tr("Status") << tr("Private") << tr("Seller Alias") << tr("Rating") << tr("Payment Options");
    priv = new OfferTablePriv(wallet, this);
    refreshOfferTable();
}

OfferTableModel::~OfferTableModel()
{
    delete priv;
}
void OfferTableModel::refreshOfferTable() 
{
	if(modelType != MyOffer)
		return;
	clear();
	priv->refreshOfferTable(modelType);
}
void OfferTableModel::filterOffers(bool showSold, bool showDigital)
{
	if(modelType != MyOffer)
		return;
	clear();
	priv->showSoldOut = showSold;
	priv->showDigitalOffers = showDigital;
	priv->refreshOfferTable(modelType);
}
int OfferTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int OfferTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant OfferTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    OfferTableEntry *rec = static_cast<OfferTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Cert:
            return rec->cert;
        case Name:
            return rec->offer;
        case Details:
            return rec->details;
        case Price:
            return rec->price;
        case Currency:
            return rec->currency;
        case Qty:
            return rec->qty;
        case Expired:
            return rec->expired;
        case Private:
            return rec->private_str;
        case Alias:
            return rec->alias;
        case AliasRating:
            return rec->aliasRating;
		case PaymentOptions:
			return rec->paymentoptions;
		case AliasPeg:
			return rec->alias_peg;
        }
    }
    else if (role == NameRole)
    {
        return rec->offer;
    }
    else if (role == TypeRole)
    {
        switch(rec->type)
        {
        case OfferTableEntry::Offer:
            return Offer;
        default: break;
        }
    }
	else if(role == CertRole)
	{
		return rec->cert;
	}
	else if(role == QtyRole)
	{
		return rec->qty;
	}
	else if(role == PriceRole)
	{
		return rec->price;
	}
	else if(role == DetailsRole)
	{
		return rec->details;
	}
	else if(role == ExpiredRole)
	{
		return rec->expired;
	}
	else if(role == PrivateRole)
	{
		return rec->private_str;
	}
	else if(role == CurrencyRole)
	{
		return rec->currency;
	}
	else if(role == AliasRole)
	{
		return rec->alias;
	}
	else if(role == AliasRatingRole)
	{
		return rec->aliasRating;
	}
	else if(role == PaymentOptionsRole)
	{
		return rec->paymentoptions;
	}
	else if(role == AliasPegRole)
	{
		return rec->alias_peg;
	}

    return QVariant();
}

bool OfferTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    OfferTableEntry *rec = static_cast<OfferTableEntry*>(index.internalPointer());
    editStatus = OK;

    if(role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Private:
	         // Do nothing, if old value == new value
            if(rec->private_str == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case Cert:
            // Do nothing, if old value == new value
            if(rec->cert == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;			
        case Price:
            // Do nothing, if old value == new value
            if(rec->price == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case Alias:
            // Do nothing, if old value == new value
            if(rec->alias == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case AliasRating:
            // Do nothing, if old value == new value
            if(rec->aliasRating == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case PaymentOptions:
            // Do nothing, if old value == new value
            if(rec->paymentoptions == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case Currency:
            // Do nothing, if old value == new value
            if(rec->currency == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case Qty:
            // Do nothing, if old value == new value
            if(rec->qty == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
        case Expired:
            // Do nothing, if old value == new value
            if(rec->expired == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
       case Details:
            // Do nothing, if old value == new value
            if(rec->details == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
       case AliasPeg:
            // Do nothing, if old value == new value
            if(rec->alias_peg == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        case Name:
            // Do nothing, if old offer == new offer
            if(rec->offer == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            // Check for duplicate offers to prevent accidental deletion of offers, if you try
            // to paste an existing offer over another offer (with a different label)
            else if(lookupOffer(rec->offer) != -1)
            {
                editStatus = DUPLICATE_OFFER;
                return false;
            }
            // Double-check that we're not overwriting a receiving offer
            else if(rec->type == OfferTableEntry::Offer)
            {
            }
            break;
        }
        return true;
    }
    return false;
}

QVariant OfferTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags OfferTableModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    return retval;
}

QModelIndex OfferTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    OfferTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void OfferTableModel::updateEntry(const QString &offer, const QString &cert, const QString &details, const QString &price, const QString &currency, const QString &qty,  const QString &expired, const QString &private_str, const QString &alias, const QString &aliasRating, const QString& paymentOptions, const QString& alias_peg, OfferModelType type, int status)
{
    // Update book model from Syscoin core
    priv->updateEntry(offer, cert, details, price, currency, qty, expired, private_str, alias, aliasRating, paymentOptions, alias_peg, type, status);
}

QString OfferTableModel::addRow(const QString &type, const QString &offer, const QString &cert, const QString &details, const QString &price, const QString &currency, const QString &qty, const QString &expired, const QString &private_str, const QString &alias, const QString &aliasRating, const QString &paymentOptions, const QString &alias_peg)
{
    std::string strOffer = offer.toStdString();
    editStatus = OK;
    // Check for duplicate offer
    {
        LOCK(wallet->cs_wallet);
        if(lookupOffer(offer) != -1)
        {
            editStatus = DUPLICATE_OFFER;
            return QString();
        }
    }

    // Add entry

    return QString::fromStdString(strOffer);
}
void OfferTableModel::clear()
{
	beginResetModel();
    priv->cachedOfferTable.clear();
	endResetModel();
}


int OfferTableModel::lookupOffer(const QString &offer) const
{
    QModelIndexList lst = match(index(0, Name, QModelIndex()),
                                Qt::EditRole, offer, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void OfferTableModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}
