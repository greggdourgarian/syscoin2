#include "offer.h"
#include "alias.h"
#include "escrow.h"
#include "cert.h"
#include "message.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "base58.h"
#include "core_io.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "consensus/validation.h"
#include "chainparams.h"
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
using namespace std;
extern void SendMoneySyscoin(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInAlias=NULL, bool syscoinMultiSigTx=false, const CCoinControl* coinControl=NULL);
bool DisconnectAlias(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool DisconnectOffer(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool DisconnectCertificate(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool DisconnectMessage(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool DisconnectEscrow(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool IsOfferOp(int op) {
	return op == OP_OFFER_ACTIVATE
        || op == OP_OFFER_UPDATE
        || op == OP_OFFER_ACCEPT;
}

bool ValidatePaymentOptionsMask(const uint32_t paymentOptionsMask) {
	uint32_t maxVal = PAYMENTOPTION_SYS | PAYMENTOPTION_BTC | PAYMENTOPTION_ZEC;
	return !(paymentOptionsMask < 1 || paymentOptionsMask > maxVal);
}


bool ValidatePaymentOptionsString(const std::string &paymentOptionsString) {
	bool retval = true;
	vector<string> strs;
	boost::split(strs, paymentOptionsString, boost::is_any_of("+"));
	for (size_t i = 0; i < strs.size(); i++) {
		if(strs[i].compare("BTC") != 0 && strs[i].compare("SYS") != 0 && strs[i].compare("ZEC") != 0) {
			retval = false;
			break;
		}
	}
	return retval;
}

uint32_t GetPaymentOptionsMaskFromString(const std::string &paymentOptionsString) {
	vector<string> strs;
	uint32_t retval = 0;
	boost::split(strs, paymentOptionsString, boost::is_any_of("+"));
	for (size_t i = 0; i < strs.size(); i++) {
		if(!strs[i].compare("SYS")) {
			retval |= PAYMENTOPTION_SYS;
		}
		else if(!strs[i].compare("BTC")) {
			retval |= PAYMENTOPTION_BTC;
		}
		else if(!strs[i].compare("ZEC")) {
			retval |= PAYMENTOPTION_ZEC;
		}
		else return 0;
	}
	return retval;
}

bool IsPaymentOptionInMask(const uint32_t mask, const uint32_t paymentOption) {
  return mask & paymentOption ? true : false;
}

int GetOfferExpirationDepth() {
	#ifdef ENABLE_DEBUGRPC
    return 1440;
  #else
    return 525600;
  #endif
}

string offerFromOp(int op) {
	switch (op) {
	case OP_OFFER_ACTIVATE:
		return "offeractivate";
	case OP_OFFER_UPDATE:
		return "offerupdate";
	case OP_OFFER_ACCEPT:
		return "offeraccept";
	default:
		return "<unknown offer op>";
	}
}
bool COffer::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsOffer(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsOffer >> *this;

		const vector<unsigned char> &vchOfferData = Serialize();
		uint256 calculatedHash = Hash(vchOfferData.begin(), vchOfferData.end());
		vector<unsigned char> vchRandOffer= vchFromValue(calculatedHash.GetHex());
		if(vchRandOffer != vchHash)
		{
			SetNull();
			return false;
		}
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	return true;
}
bool COffer::UnserializeFromTx(const CTransaction &tx) {
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	int nOut;
	if(!GetSyscoinData(tx, vchData, vchHash, nOut))
	{
		SetNull();
		return false;
	}
	if(!UnserializeFromData(vchData, vchHash))
	{
		return false;
	}
    return true;
}
const vector<unsigned char> COffer::Serialize() {
    CDataStream dsOffer(SER_NETWORK, PROTOCOL_VERSION);
    dsOffer << *this;
    const vector<unsigned char> vchData(dsOffer.begin(), dsOffer.end());
    return vchData;

}
bool COfferDB::ScanOffers(const std::vector<unsigned char>& vchOffer, const string& strRegexp, bool safeSearch,const string& strCategory, unsigned int nMax,
		std::vector<std::pair<std::vector<unsigned char>, COffer> >& offerScan) {
   // regexp
    using namespace boost::xpressive;
    smatch offerparts;
	smatch nameparts;
	string strRegexpLower = strRegexp;
	boost::algorithm::to_lower(strRegexpLower);
	sregex cregex = sregex::compile(strRegexpLower);
	int nMaxAge  = GetOfferExpirationDepth();
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->Seek(make_pair(string("offeri"), vchOffer));
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
		pair<string, vector<unsigned char> > key;
        try {
			if (pcursor->GetKey(key) && key.first == "offeri") {
            	vector<unsigned char> vchOffer = key.second;
                vector<COffer> vtxPos;
				pcursor->GetValue(vtxPos);

				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const COffer &txPos = vtxPos.back();
				int nQty = txPos.nQty;
  				if (chainActive.Tip()->nHeight - txPos.nHeight >= nMaxAge)
				{
					pcursor->Next();
					continue;
				}
				CAliasIndex linkAlias;
				if( !txPos.vchLinkOffer.empty())
				{
					vector<COffer> myLinkedOfferVtxPos;
					vector<CAliasIndex> myLinkedAliasVtxPos;
					if (!pofferdb->ReadOffer(txPos.vchLinkOffer, myLinkedOfferVtxPos) || myLinkedOfferVtxPos.empty())
					{
						pcursor->Next();
						continue;
					}
					const COffer &linkOffer = myLinkedOfferVtxPos.back();
					nQty = linkOffer.nQty;
					if (!paliasdb->ReadAlias(linkOffer.vchAlias, myLinkedAliasVtxPos) || myLinkedAliasVtxPos.empty())
					{
						pcursor->Next();
						continue;
					}

					linkAlias = myLinkedAliasVtxPos.back();
					if(linkOffer.safetyLevel >= SAFETY_LEVEL1 || linkAlias.safetyLevel >= SAFETY_LEVEL1)
					{
						if(safeSearch)
						{
							pcursor->Next();
							continue;
						}
						if(linkOffer.safetyLevel >= SAFETY_LEVEL2 || linkAlias.safetyLevel >= SAFETY_LEVEL2)
						{
							pcursor->Next();
							continue;
						}
					}
					if((!linkOffer.safeSearch || !linkAlias.safeSearch) && safeSearch)
					{
						pcursor->Next();
						continue;
					}
				}
				// dont return sold out offers
				if(nQty <= 0 && nQty != -1)
				{
					pcursor->Next();
					continue;
				}
				CAliasIndex theAlias;
				CTransaction aliastx;
				if(!GetTxOfAlias(txPos.vchAlias, theAlias, aliastx))
				{
					pcursor->Next();
					continue;
				}
				if(txPos.safetyLevel >= SAFETY_LEVEL1  || linkAlias.safetyLevel >= SAFETY_LEVEL1)
				{
					if(safeSearch)
					{
						pcursor->Next();
						continue;
					}
					if(txPos.safetyLevel >= SAFETY_LEVEL2 || linkAlias.safetyLevel >= SAFETY_LEVEL2)
					{
						pcursor->Next();
						continue;
					}
				}
				if((!txPos.safeSearch || !theAlias.safeSearch) && safeSearch)
				{
					pcursor->Next();
					continue;
				}
				if(strCategory.size() > 0 && !boost::algorithm::starts_with(stringFromVch(txPos.sCategory), strCategory))
				{
					pcursor->Next();
					continue;
				}

				string title = stringFromVch(txPos.sTitle);
				string offer = stringFromVch(vchOffer);
				boost::algorithm::to_lower(title);
				string description = stringFromVch(txPos.sDescription);
				boost::algorithm::to_lower(description);
				if(!theAlias.safeSearch && safeSearch)
				{
					pcursor->Next();
					continue;
				}
				if((safeSearch && theAlias.safetyLevel > txPos.safetyLevel) || (!safeSearch && theAlias.safetyLevel > SAFETY_LEVEL1))
				{
					pcursor->Next();
					continue;
				}
				string alias = stringFromVch(txPos.vchAlias);
				if (strRegexp != "" && !regex_search(title, offerparts, cregex) && !regex_search(description, offerparts, cregex) && strRegexp != offer && strRegexpLower != alias)
				{
					pcursor->Next();
					continue;
				}
				if(txPos.bPrivate)
				{
					if(strRegexp == "")
					{
						pcursor->Next();
						continue;
					}
					else if(strRegexp != offer)
					{
						pcursor->Next();
						continue;
					}
				}
                offerScan.push_back(make_pair(vchOffer, txPos));
            }
            if (offerScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}

int IndexOfOfferOutput(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return -1;
	vector<vector<unsigned char> > vvch;
	int op;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeOfferScript(out.scriptPubKey, op, vvch)) {
			return i;
		}
	}
	return -1;
}

bool GetTxOfOffer(const vector<unsigned char> &vchOffer,
				  COffer& txPos, CTransaction& tx, bool skipExpiresCheck) {
	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;

	if (!skipExpiresCheck && (nHeight + GetOfferExpirationDepth()
			< chainActive.Tip()->nHeight)) {
		string offer = stringFromVch(vchOffer);
		if(fDebug)
			LogPrintf("GetTxOfOffer(%s) : expired", offer.c_str());
		return false;
	}

	if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return false;

	return true;
}
bool GetTxAndVtxOfOffer(const vector<unsigned char> &vchOffer,
				  COffer& txPos, CTransaction& tx, vector<COffer> &vtxPos, bool skipExpiresCheck) {
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		return false;

	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;

	if (!skipExpiresCheck && (nHeight + GetOfferExpirationDepth()
			< chainActive.Tip()->nHeight)) {
		string offer = stringFromVch(vchOffer);
		if(fDebug)
			LogPrintf("GetTxOfOffer(%s) : expired", offer.c_str());
		return false;
	}

	if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return false;

	return true;
}
bool GetTxOfOfferAccept(const vector<unsigned char> &vchOffer, const vector<unsigned char> &vchOfferAccept,
		COffer &acceptOffer,  COfferAccept &theOfferAccept, CTransaction& tx, bool skipExpiresCheck) {
	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty()) return false;
	theOfferAccept.SetNull();
	theOfferAccept.vchAcceptRand = vchOfferAccept;
	if(!GetAcceptByHash(vtxPos, theOfferAccept, acceptOffer))
		return false;

	if (!skipExpiresCheck && ( vtxPos.back().nHeight + GetOfferExpirationDepth())
			< chainActive.Tip()->nHeight) {
		string offer = stringFromVch(vchOfferAccept);
		if(fDebug)
			LogPrintf("GetTxOfOfferAccept(%s) : expired", offer.c_str());
		return false;
	}

	if (!GetSyscoinTransaction(acceptOffer.nHeight, acceptOffer.txHash, tx, Params().GetConsensus()))
		return false;

	return true;
}
bool DecodeAndParseOfferTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	COffer offer;
	bool decode = DecodeOfferTx(tx, op, nOut, vvch);
	bool parse = offer.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeOfferTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch) {
	bool found = false;

	// Strict check - bug disallowed
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (DecodeOfferScript(out.scriptPubKey, op, vvch)) {
			nOut = i; found = true;
			break;
		}
	}
	if (!found) vvch.clear();
	return found;
}
int FindOfferAcceptPayment(const CTransaction& tx, const CAmount &nPrice) {
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		if(tx.vout[i].nValue == nPrice)
			return i;
	}
	return -1;
}

bool DecodeOfferScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
	opcodetype opcode;
	vvch.clear();
	if (!script.GetOp(pc, opcode)) return false;
	if (opcode < OP_1 || opcode > OP_16) return false;
	op = CScript::DecodeOP_N(opcode);

	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
			break;
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;
	return IsOfferOp(op);
}
bool DecodeOfferScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeOfferScript(script, op, vvch, pc);
}
CScript RemoveOfferScriptPrefix(const CScript& scriptIn) {
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeOfferScript(scriptIn, op, vvch, pc))
	{
		throw runtime_error(
			"RemoveOfferScriptPrefix() : could not decode offer script");
	}

	return CScript(pc, scriptIn.end());
}

bool CheckOfferInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, const CBlock* block, bool dontaddtodb) {

	if(!IsSys21Fork(nHeight))
		return true;
	if (tx.IsCoinBase())
		return true;
	if (fDebug)
		LogPrintf("*** OFFER %d %d %s %s %s %s %s %d\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			op==OP_OFFER_ACCEPT ? "OFFERACCEPT: ": "",
			op==OP_OFFER_ACCEPT && vvchArgs.size() > 1? stringFromVch(vvchArgs[1]).c_str(): "",
			fJustCheck ? "JUSTCHECK" : "BLOCK", " VVCH SIZE: ", vvchArgs.size());
	bool foundAlias = false;
	const COutPoint *prevOutput = NULL;
	const CCoins *prevCoins;
	int prevAliasOp = 0;
	vector<vector<unsigned char> > vvchPrevAliasArgs;
	// unserialize msg from txn, check for valid
	COffer theOffer;
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	CTxDestination payDest, commissionDest, dest, aliasDest, linkDest;
	int nDataOut;
	if(!GetSyscoinData(tx, vchData, vchHash, nDataOut) || !theOffer.UnserializeFromData(vchData, vchHash))
	{
		errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR ERRCODE: 1000 - " + _("Cannot unserialize data inside of this transaction relating to an offer");
		return true;
	}
	// Make sure offer outputs are not spent by a regular transaction, or the offer would be lost
	if (tx.nVersion != SYSCOIN_TX_VERSION)
	{
		errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1001 - " + _("Non-Syscoin transaction found");
		return true;
	}
	if(fJustCheck)
	{
		if(op != OP_OFFER_ACCEPT && vvchArgs.size() != 2)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1003 - " + _("Offer arguments incorrect size");
			return error(errorMessage.c_str());
		}
		else if(op == OP_OFFER_ACCEPT && vvchArgs.size() != 4)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1004 - " + _("OfferAccept arguments incorrect size");
			return error(errorMessage.c_str());
		}
		if(!theOffer.IsNull())
		{
			if(op == OP_OFFER_ACCEPT)
			{
				if(vvchArgs.size() <= 3 || vchHash != vvchArgs[3])
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1005 - " + _("Hash provided doesn't match the calculated hash of the data");
					return error(errorMessage.c_str());
				}
			}
			else
			{
				if(vvchArgs.size() <= 1 || vchHash != vvchArgs[1])
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1006 - " + _("Hash provided doesn't match the calculated hash of the data");
					return error(errorMessage.c_str());
				}
			}
		}


		// Strict check - bug disallowed
		for (unsigned int i = 0; i < tx.vin.size(); i++) {
			vector<vector<unsigned char> > vvch;
			int pop;
			prevOutput = &tx.vin[i].prevout;
			if(!prevOutput)
				continue;
			// ensure inputs are unspent when doing consensus check to add to block
			prevCoins = inputs.AccessCoins(prevOutput->hash);
			if(prevCoins == NULL)
				continue;
			if(prevCoins->vout.size() <= prevOutput->n || !IsSyscoinScript(prevCoins->vout[prevOutput->n].scriptPubKey, pop, vvch) || pop == OP_ALIAS_PAYMENT)
				continue;

			if (!foundAlias && IsAliasOp(pop))
			{
				foundAlias = true;
				prevAliasOp = pop;
				vvchPrevAliasArgs = vvch;
			}
		}

	}


	// unserialize offer from txn, check for valid
	COfferAccept theOfferAccept;
	vector<CAliasIndex> vtxAliasPos;
	COffer linkOffer;
	COffer myPriceOffer;
	COffer myOffer;
	CTransaction linkedTx;
	COfferLinkWhitelistEntry entry;
	CCert theCert;
	CAliasIndex theAlias, alias, linkAlias;
	CTransaction aliasTx, aliasLinkTx;
	vector<COffer> vtxPos;
	vector<string> rateList;
	vector<string> categories;
	vector<COffer> offerVtxPos;
	string category;
	int precision = 2;
	int nFeePerByte;
	double nRate;
	float fEscrowFee;
	string retError = "";
	// just check is for the memory pool inclusion, here we can stop bad transactions from entering before we get to include them in a block
	if(fJustCheck)
	{
		if (vvchArgs.empty() || vvchArgs[0].size() > MAX_GUID_LENGTH)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1007 - " + _("Offer guid too long");
			return error(errorMessage.c_str());
		}

		if(theOffer.sDescription.size() > MAX_VALUE_LENGTH)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1008 - " + _("Offer description too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.sTitle.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1009 - " + _("Offer title too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.sCategory.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1010 - " + _("Offer category too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.vchLinkOffer.size() > MAX_GUID_LENGTH)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1011 - " + _("Offer link guid hash too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.sCurrencyCode.size() > MAX_GUID_LENGTH)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1012 - " + _("Offer curreny too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.vchGeoLocation.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1014 - " + _("Offer geolocation too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.linkWhitelist.entries.size() > 1)
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1016 - " + _("Offer has too many affiliate entries, only one allowed per transaction");
			return error(errorMessage.c_str());
		}
		if(!theOffer.vchOffer.empty() && theOffer.vchOffer != vvchArgs[0])
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1017 - " + _("Offer guid in the data output does not match the guid in the transaction");
			return error(errorMessage.c_str());
		}
		switch (op) {
		case OP_OFFER_ACTIVATE:
			if(!IsAliasOp(prevAliasOp) || theOffer.vchAlias != vvchPrevAliasArgs[0])
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1021 - " + _("Alias input mismatch");
				return error(errorMessage.c_str());
			}
			if(!ValidatePaymentOptionsMask(theOffer.paymentOptions))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1018 - " + _("Invalid payment option");
				return error(errorMessage.c_str());
			}
			if(!theOffer.accept.IsNull())
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1019 - " + _("Cannot have accept information on offer activation");
				return error(errorMessage.c_str());
			}
			if ( theOffer.vchOffer != vvchArgs[0])
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1020 - " + _("Offer input and offer guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!theOffer.vchLinkOffer.empty())
			{
				if(theOffer.nCommission > 100 || theOffer.nCommission < -90)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1022 - " + _("Commission must between -90 and 100");
					return error(errorMessage.c_str());
				}
			}
			else
			{
				if(theOffer.sCategory.size() < 1)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1023 - " + _("Offer category cannot be empty");
					return error(errorMessage.c_str());
				}
				if(theOffer.sTitle.size() < 1)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1024 - " + _("Offer title cannot be empty");
					return error(errorMessage.c_str());
				}
				if(theOffer.paymentOptions <= 0)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1025 - " + _("Invalid payment option specified");
					return error(errorMessage.c_str());
				}
			}
			if(theOffer.nQty < -1)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1026 - " + _("Quantity must be greater than or equal to -1");
				return error(errorMessage.c_str());
			}
			if(!theOffer.vchCert.empty() && theOffer.nQty != 1)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1027 - " + _("Quantity must be 1 for a digital offer");
				return error(errorMessage.c_str());
			}
			if(theOffer.nPrice <= 0)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1028 - " + _("Offer price must be greater than 0");
				return error(errorMessage.c_str());
			}


			break;
		case OP_OFFER_UPDATE:
			if(!IsAliasOp(prevAliasOp) || theOffer.vchAlias != vvchPrevAliasArgs[0])
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1021 - " + _("Alias input mismatch");
				return error(errorMessage.c_str());
			}
			if(theOffer.paymentOptions > 0 && !ValidatePaymentOptionsMask(theOffer.paymentOptions))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1029 - " + _("Invalid payment option");
				return error(errorMessage.c_str());
			}
			if(!theOffer.accept.IsNull())
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1030 - " + _("Cannot have accept information on offer update");
				return error(errorMessage.c_str());
			}
			if ( theOffer.vchOffer != vvchArgs[0])
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1034 - " + _("Offer input and offer guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!theOffer.linkWhitelist.entries.empty() && theOffer.linkWhitelist.entries[0].nDiscountPct > 99 && theOffer.linkWhitelist.entries[0].nDiscountPct != 127)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1035 - " + _("Discount must be between 0 and 99");
				return error(errorMessage.c_str());
			}

			if(theOffer.nQty < -1)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1036 - " + _("Quantity must be greater than or equal to -1");
				return error(errorMessage.c_str());
			}
			if(!theOffer.vchCert.empty() && theOffer.nQty != 1)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1037 - " + _("Quantity must be 1 for a digital offer");
				return error(errorMessage.c_str());
			}
			if(theOffer.nPrice <= 0)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1038 - " + _("Offer price must be greater than 0");
				return error(errorMessage.c_str());
			}
			if(theOffer.nCommission > 100 || theOffer.nCommission < -90)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1039 - " + _("Commission must between -90 and 100");
				return error(errorMessage.c_str());
			}
			break;
		case OP_OFFER_ACCEPT:
			theOfferAccept = theOffer.accept;
			if(!IsAliasOp(prevAliasOp) || theOfferAccept.vchBuyerAlias != vvchPrevAliasArgs[0])
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1021 - " + _("Alias input mismatch");
				return error(errorMessage.c_str());
			}
			if(!theOfferAccept.feedback.empty())
			{
				if(vvchArgs.size() <= 2 || vvchArgs[2] != vchFromString("1"))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1041 - " + _("Invalid feedback transaction");
					return error(errorMessage.c_str());
				}
				if(theOfferAccept.feedback[0].vchFeedback.empty())
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1044 - " + _("Cannot leave empty feedback");
					return error(errorMessage.c_str());
				}
				if(theOfferAccept.feedback.size() > 1)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1045 - " + _("Cannot only leave one feedback per transaction");
					return error(errorMessage.c_str());
				}
				break;
			}
			else
			{
                if(!ValidatePaymentOptionsMask(theOfferAccept.nPaymentOption))
                {
                    errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1018 - " + _("Invalid payment option");
                    return error(errorMessage.c_str());
                }
			}

			if (theOfferAccept.IsNull())
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1046 - " + _("Offeraccept object cannot be empty");
				return error(errorMessage.c_str());
			}
			if (!IsValidAliasName(theOfferAccept.vchBuyerAlias))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1047 - " + _("Invalid offer buyer alias");
				return error(errorMessage.c_str());
			}
			if (vvchArgs.size() <= 1 || vvchArgs[1].size() > MAX_GUID_LENGTH)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1049 - " + _("Offeraccept transaction with guid too big");
				return error(errorMessage.c_str());
			}
			if (theOfferAccept.vchAcceptRand.size() > MAX_GUID_LENGTH)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1050 - " + _("Offer accept hex guid too long");
				return error(errorMessage.c_str());
			}
			if (theOfferAccept.vchMessage.size() > MAX_ENCRYPTED_VALUE_LENGTH)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1051 - " + _("Message field too big");
				return error(errorMessage.c_str());
			}
			if (theOffer.vchOffer != vvchArgs[0])
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1052 - " + _("Offer input and offer guid mismatch");
				return error(errorMessage.c_str());
			}

			break;

		default:
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1053 - " + _("Offer transaction has unknown op");
			return error(errorMessage.c_str());
		}
	}


	if (!fJustCheck ) {
		COffer serializedOffer;
		if(op != OP_OFFER_ACTIVATE) {
			// save serialized offer for later use
			serializedOffer = theOffer;
			CTransaction offerTx;
			// load the offer data from the DB

			if(!GetTxAndVtxOfOffer(vvchArgs[0], theOffer, offerTx, vtxPos))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1054 - " + _("Failed to read from offer DB");
				return true;
			}
		}
		// If update, we make the serialized offer the master
		// but first we assign fields from the DB since
		// they are not shipped in an update txn to keep size down
		if(op == OP_OFFER_UPDATE) {
			serializedOffer.vchLinkOffer = theOffer.vchLinkOffer;
			serializedOffer.vchOffer = theOffer.vchOffer;
			serializedOffer.nSold = theOffer.nSold;
			// cannot edit safety level
			serializedOffer.safetyLevel = theOffer.safetyLevel;
			serializedOffer.accept.SetNull();
			theOffer = serializedOffer;
			if(!vtxPos.empty())
			{
				const COffer& dbOffer = vtxPos.back();
				// if updating whitelist, we dont allow updating any offer details
				if(theOffer.linkWhitelist.entries.size() > 0)
					theOffer = dbOffer;
				else
				{
					// whitelist must be preserved in serialOffer and db offer must have the latest in the db for whitelists
					theOffer.linkWhitelist.entries = dbOffer.linkWhitelist.entries;
					// some fields are only updated if they are not empty to limit txn size, rpc sends em as empty if we arent changing them
					if(serializedOffer.sCategory.empty())
						theOffer.sCategory = dbOffer.sCategory;
					if(serializedOffer.sTitle.empty())
						theOffer.sTitle = dbOffer.sTitle;
					if(serializedOffer.sDescription.empty())
						theOffer.sDescription = dbOffer.sDescription;
					if(serializedOffer.vchCert.empty())
						theOffer.vchCert = dbOffer.vchCert;
					if(serializedOffer.vchGeoLocation.empty())
						theOffer.vchGeoLocation = dbOffer.vchGeoLocation;
					if(serializedOffer.sCurrencyCode.empty())
						theOffer.sCurrencyCode = dbOffer.sCurrencyCode;
					if(serializedOffer.paymentOptions <= 0)
						theOffer.paymentOptions = dbOffer.paymentOptions;

					// user can't update safety level after creation
					theOffer.safetyLevel = dbOffer.safetyLevel;
					if(!theOffer.vchCert.empty())
					{
						CTransaction txCert;
						if (!GetTxOfCert( theOffer.vchCert, theCert, txCert))
						{
							errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1055 - " + _("Updating an offer with a cert that does not exist");
							theOffer.vchCert.clear();
						}
						else if(theOffer.vchLinkOffer.empty() && theCert.vchAlias != theOffer.vchAlias)
						{
							errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1056 - " + _("Cannot update this offer because the certificate alias does not match the offer alias");
							theOffer.vchAlias = dbOffer.vchAlias;
						}
					}
					if(!theOffer.vchLinkOffer.empty())
					{
						CTransaction txLinkedOffer;
						if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, txLinkedOffer, offerVtxPos))
						{
							errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1057 - " + _("Linked offer not found. It may be expired");
							theOffer.vchLinkOffer.clear();
						}
						else if(linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, entry))
						{
							if(theOffer.nCommission <= -entry.nDiscountPct)
							{
								errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1058 - " + _("This resold offer must be of higher price than the original offer including any discount");
								theOffer.vchLinkOffer.clear();
							}
						}
						// make sure alias exists in the root offer affiliate list if root offer is in exclusive mode
						else if (linkOffer.linkWhitelist.bExclusiveResell)
						{
							errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1059 - " + _("Cannot find this alias in the parent offer affiliate list");
							theOffer.vchLinkOffer.clear();
						}
						if (!linkOffer.vchLinkOffer.empty())
						{
							errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1060 - " + _("Cannot link to an offer that is already linked to another offer");
							theOffer.vchLinkOffer.clear();
						}
						else if(linkOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(linkOffer.sCategory), "wanted"))
						{
							errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1061 - " + _("Cannot link to a wanted offer");
							theOffer.vchLinkOffer.clear();
						}
						else if(!theOffer.vchCert.empty() && theCert.vchAlias != linkOffer.vchAlias)
						{
							errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1062 - " + _("Cannot update this offer because the certificate alias does not match the linked offer alias");
							theOffer.vchAlias = dbOffer.vchAlias;
						}
					}
					// non linked offers cant edit commission
					else
						theOffer.nCommission = 0;
					if(theOffer.vchAlias != dbOffer.vchAlias)
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1063 - " + _("Wrong alias input provided in this offer update transaction");
						theOffer.vchAlias = dbOffer.vchAlias;
					}
					else if(!theOffer.vchLinkAlias.empty())
						theOffer.vchAlias = theOffer.vchLinkAlias;
					theOffer.vchLinkAlias.clear();
					if(!GetTxOfAlias(theOffer.vchAlias, alias, aliasTx))
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1064 - " + _("Cannot find alias for this offer. It may be expired");
						theOffer = dbOffer;
					}
					// check for valid alias peg
					if(getCurrencyToSYSFromAlias(alias.vchAliasPeg, theOffer.sCurrencyCode, nRate, theOffer.nHeight, rateList,precision, nFeePerByte, fEscrowFee) != "")
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1065 - " + _("Could not find currency in the peg alias");
						return true;
					}
				}
			}
		}
		else if(op == OP_OFFER_ACTIVATE)
		{
			if(!GetTxOfAlias(theOffer.vchAlias, alias, aliasTx))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1066 - " + _("Cannot find alias for this offer. It may be expired");
				return true;
			}
			if (pofferdb->ExistsOffer(vvchArgs[0]))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1067 - " + _("Offer already exists");
				return true;
			}
			// if we are selling a cert ensure it exists and pubkey's match (to ensure it doesnt get transferred prior to accepting by user)
			if(!theOffer.vchCert.empty())
			{
				CTransaction txCert;
				if (!GetTxOfCert( theOffer.vchCert, theCert, txCert))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1068 - " + _("Creating an offer with a cert that does not exist");
					return true;
				}
				else if(theOffer.vchLinkOffer.empty() && theCert.vchAlias != theOffer.vchAlias)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1069 - " + _("Cannot create this offer because the certificate alias does not match the offer alias");
					return true;
				}
			}
			// if this is a linked offer activate, then add alias to the whitelist
			if(!theOffer.vchLinkOffer.empty())
			{
				CTransaction txLinkedOffer;
				if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, txLinkedOffer, offerVtxPos))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1070 - " + _("Linked offer not found. It may be expired");
					theOffer.vchLinkOffer.clear();
				}
				else if(linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, entry))
				{
					if(theOffer.nCommission <= -entry.nDiscountPct)
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1071 - " + _("This resold offer must be of higher price than the original offer including any discount");
						theOffer.vchLinkOffer.clear();
					}
				}
				// make sure alias exists in the root offer affiliate list if root offer is in exclusive mode
				else if (linkOffer.linkWhitelist.bExclusiveResell)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1072 - " + _("Cannot find this alias in the parent offer affiliate list");
					theOffer.vchLinkOffer.clear();
				}
				if (!linkOffer.vchLinkOffer.empty())
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1074 - " + _("Cannot link to an offer that is already linked to another offer");
					theOffer.vchLinkOffer.clear();
				}
				else if(linkOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(linkOffer.sCategory), "wanted"))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1075 - " + _("Cannot link to a wanted offer");
					theOffer.vchLinkOffer.clear();
				}
				else if(!theOffer.vchCert.empty() && theCert.vchAlias != linkOffer.vchAlias)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1076 -" + _("Cannot create this offer because the certificate alias does not match the offer alias");
					theOffer.vchLinkOffer.clear();
				}
				else if(linkOffer.linkWhitelist.entries.size() > 20)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1076 -" + _("Too many affiliates for this offer");
					theOffer.vchLinkOffer.clear();
				}
				else if(!theOffer.vchLinkOffer.empty())
				{
					// if creating a linked offer we set some mandatory fields to the parent
					theOffer.nQty = linkOffer.nQty;
					theOffer.linkWhitelist.bExclusiveResell = true;
					theOffer.sCurrencyCode = linkOffer.sCurrencyCode;
					theOffer.vchCert = linkOffer.vchCert;
					theOffer.SetPrice(linkOffer.nPrice);
					theOffer.sCategory = linkOffer.sCategory;
					theOffer.sTitle = linkOffer.sTitle;
					theOffer.safeSearch = linkOffer.safeSearch;
					theOffer.paymentOptions = linkOffer.paymentOptions;
					COfferLinkWhitelistEntry addEntry;
					addEntry.aliasLinkVchRand = theOffer.vchAlias;
					linkOffer.linkWhitelist.PutWhitelistEntry(addEntry);
					linkOffer.PutToOfferList(offerVtxPos);
					// write parent offer

					if (!dontaddtodb && !pofferdb->WriteOffer(theOffer.vchLinkOffer, offerVtxPos))
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1077 - " + _("Failed to write to offer link to DB");
						return error(errorMessage.c_str());
					}
				}
			}
			else
			{
				// check for valid alias peg
				if(getCurrencyToSYSFromAlias(alias.vchAliasPeg, theOffer.sCurrencyCode, nRate, theOffer.nHeight, rateList,precision, nFeePerByte, fEscrowFee) != "")
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1079 - " + _("Could not find currency in the peg alias");
					return true;
				}
			}
			// init sold to 0
			theOffer.nSold = 0;
		}
		else if (op == OP_OFFER_ACCEPT) {
			theOfferAccept = serializedOffer.accept;
			CAliasIndex buyeralias;
			CTransaction buyeraliasTx;
			CTransaction acceptTx;
			COfferAccept offerAccept;
			COffer acceptOffer;
			if(!GetTxOfAlias(theOfferAccept.vchBuyerAlias, buyeralias, buyeraliasTx))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1080 - " + _("Cannot find buyer alias. It may be expired");
				return true;
			}
			if(theOfferAccept.bPaymentAck)
			{
				if(theOfferAccept.vchBuyerAlias != theOffer.vchAlias)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1081 - " + _("Only seller can acknowledge offer payment");
					return true;
				}
				if (!GetTxOfOfferAccept(vvchArgs[0], vvchArgs[1], acceptOffer, offerAccept, acceptTx))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1081 - " + _("Could not find offer accept from mempool or disk");
					return true;
				}
				if(!acceptOffer.vchLinkOffer.empty())
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1081 - " + _("Could not acknowledge payment for linked offer");
					return true;
				}			
				if(offerAccept.bPaymentAck)
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4041 - " + _("Offer payment already acknowledged");
					return true;
				}

				int nQty = theOffer.nQty;
				if(nQty != -1)
				{
					if(offerAccept.nQty > nQty)
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1105 - " + _("Not enough quantity left in this offer for this purchase");
						return true;
					}
					nQty -= offerAccept.nQty;
				}
				theOffer.nSold++;
				theOffer.nQty = nQty;
				theOffer.txHash = tx.GetHash();
				theOffer.accept = offerAccept;
				theOffer.accept.bPaymentAck = true;
				theOffer.nHeight = nHeight;
				theOffer.PutToOfferList(vtxPos);
				// write offer

				if (!dontaddtodb && !pofferdb->WriteOffer(vvchArgs[0], vtxPos))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1123 - " + _("Failed to write to offer DB");
					return error(errorMessage.c_str());
				}
				if (fDebug)
					LogPrintf( "CONNECTED OFFER ACK: op=%s offer=%s title=%s qty=%u hash=%s height=%d\n",
						offerFromOp(op).c_str(),
						stringFromVch(vvchArgs[0]).c_str(),
						stringFromVch(theOffer.sTitle).c_str(),
						theOffer.nQty,
						tx.GetHash().ToString().c_str(),
						nHeight);
				return true;
			}
			else if(!theOfferAccept.feedback.empty())
			{
				if (!GetTxOfOfferAccept(vvchArgs[0], vvchArgs[1], acceptOffer, offerAccept, acceptTx))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1081 - " + _("Could not find offer accept from mempool or disk");
					return true;
				}
				// if feedback is for buyer then we need to ensure attached input alias was from seller
				if(theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER)
				{
					if(theOfferAccept.vchBuyerAlias != offerAccept.vchBuyerAlias)
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1082 - " + _("Only seller can leaver the buyer feedback");
						return true;
					}
				}
				else if(theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER)
				{
					if(theOfferAccept.vchBuyerAlias != acceptOffer.vchAlias)
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1083 - " + _("Only buyer can leave the seller feedback");
						return true;
					}
				}
				else
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1084 - " + _("Unknown feedback user type");
					return true;
				}
				if(!acceptOffer.vchLinkOffer.empty())
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1085 - " + _("Cannot leave feedback for linked offers");
					return true;
				}
				int numBuyerRatings, numSellerRatings, feedbackBuyerCount, numArbiterRatings, feedbackSellerCount, feedbackArbiterCount;
				FindFeedback(offerAccept.feedback, numBuyerRatings, numSellerRatings, numArbiterRatings,feedbackBuyerCount, feedbackSellerCount, feedbackArbiterCount);
				// has this user already rated? if so set desired rating to 0
				if(theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER && numBuyerRatings > 0)
					theOfferAccept.feedback[0].nRating = 0;
				else if(theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER && numSellerRatings > 0)
					theOfferAccept.feedback[0].nRating = 0;
				if(feedbackBuyerCount >= 10 && theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1086 - " + _("Cannot exceed 10 buyer feedbacks");
					return true;
				}
				else if(feedbackSellerCount >= 10 && theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1087 - " + _("Cannot exceed 10 seller feedbacks");
					return true;
				}
				theOfferAccept.feedback[0].txHash = tx.GetHash();
				theOfferAccept.feedback[0].nHeight = nHeight;
				if(!dontaddtodb)
					HandleAcceptFeedback(theOfferAccept.feedback[0], acceptOffer, vtxPos);
				if (fDebug)
					LogPrintf( "CONNECTED OFFER FEEDBACK: op=%s offer=%s title=%s qty=%u hash=%s height=%d\n",
						offerFromOp(op).c_str(),
						stringFromVch(vvchArgs[0]).c_str(),
						stringFromVch(theOffer.sTitle).c_str(),
						theOffer.nQty,
						tx.GetHash().ToString().c_str(),
						nHeight);
				return true;

			}
			if (GetTxOfOfferAccept(vvchArgs[0], vvchArgs[1], acceptOffer, offerAccept, acceptTx))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1088 - " + _("Offer payment already exists");
				return true;
			}

			myPriceOffer.nHeight = theOfferAccept.nAcceptHeight;

			// if linked offer then get offer info from root offer history because the linked offer may not have history of changes (root offer can update linked offer without tx)
			myPriceOffer.GetOfferFromList(vtxPos);
			if(!GetTxOfAlias(myPriceOffer.vchAlias, alias, aliasTx))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1091 - " + _("Cannot find alias for this offer. It may be expired");
				return true;
			}
			// trying to purchase a cert
			if(!myPriceOffer.vchCert.empty())
			{
				CTransaction txCert;
				if (!GetTxOfCert( myPriceOffer.vchCert, theCert, txCert))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1092 - " + _("Cannot sell an expired certificate");
					return true;
				}
				else if(!theOfferAccept.txExtId.IsNull())
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1093 - " + _("Cannot purchase certificates with Bitcoins");
					return true;
				}
				else if(myPriceOffer.vchLinkOffer.empty())
				{
					if(theCert.vchAlias != myPriceOffer.vchAlias)
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1094 - " + _("Cannot purchase this offer because the certificate has been transferred or it is linked to another offer");
						return true;
					}
				}
			}
			else if (theOfferAccept.vchMessage.size() <= 0)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1095 - " + _("Offer payment message cannot be empty");
				return true;
			}
			if(!myPriceOffer.vchLinkOffer.empty())
			{
				if(!GetTxAndVtxOfOffer( myPriceOffer.vchLinkOffer, linkOffer, linkedTx, offerVtxPos))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1096 - " + _("Could not get linked offer");
					return true;
				}
				linkOffer.nHeight = theOfferAccept.nAcceptHeight;
				linkOffer.GetOfferFromList(offerVtxPos);
				if(!GetTxOfAlias(linkOffer.vchAlias, linkAlias, aliasLinkTx))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1097 - " + _("Cannot find alias for this linked offer. It may be expired");
					return true;
				}
				else if(!myPriceOffer.vchCert.empty() && theCert.vchAlias != linkOffer.vchAlias)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1098 - " + _("Cannot purchase this linked offer because the certificate has been transferred or it is linked to another offer");
					return true;
				}
				else if(linkOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(linkOffer.sCategory), "wanted"))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1099 - " + _("Cannot purchase a wanted offer");
					return true;
				}
				else if(!IsPaymentOptionInMask(linkOffer.paymentOptions, theOfferAccept.nPaymentOption))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1089 - " + _("User selected payment option not found in list of accepted offer payment options");
					return true;
				}
				else if(!theOfferAccept.txExtId.IsNull() && (linkOffer.paymentOptions == PAYMENTOPTION_SYS || theOfferAccept.nPaymentOption == PAYMENTOPTION_SYS))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1090 - " + _("External chain payment cannot be made with this offer");
					return true;
				}
				linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, entry);
				if(entry.IsNull())
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1102 - " + _("Linked offer alias does not exist on the root offer affiliate list");
					return true;
				}
			}
			else
			{
				if(!IsPaymentOptionInMask(myPriceOffer.paymentOptions, theOfferAccept.nPaymentOption))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1089 - " + _("User selected payment option not found in list of accepted offer payment options");
					return true;
				}
				else if(!theOfferAccept.txExtId.IsNull() && (myPriceOffer.paymentOptions == PAYMENTOPTION_SYS || theOfferAccept.nPaymentOption == PAYMENTOPTION_SYS))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1090 - " + _("External chain payment cannot be made with this offer");
					return true;
				}
			}
			if(theOfferAccept.txExtId.IsNull() && theOfferAccept.nPaymentOption != PAYMENTOPTION_SYS)
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1090 - " + _("External chain payment txid missing");
				return true;
			}
			if(myPriceOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(myPriceOffer.sCategory), "wanted"))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1103 - " + _("Cannot purchase a wanted offer");
				return true;
			}


			// check that user pays enough in syscoin if the currency of the offer is not external purchase
			if(theOfferAccept.txExtId.IsNull())
			{
				CAmount nPrice;
				CAmount nCommission;
				// try to get the whitelist entry here from the sellers whitelist, apply the discount with GetPrice()
				if(myPriceOffer.vchLinkOffer.empty())
				{
					myPriceOffer.linkWhitelist.GetLinkEntryByHash(theOfferAccept.vchBuyerAlias, entry);
					nPrice = myPriceOffer.GetPrice(entry);
					nCommission = 0;
				}
				else
				{
					linkOffer.linkWhitelist.GetLinkEntryByHash(myPriceOffer.vchAlias, entry);
					nPrice = linkOffer.GetPrice(entry);
					nCommission = myPriceOffer.GetPrice() - nPrice;
				}


				if(nPrice != theOfferAccept.nPrice)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1107 - " + _("Offer payment does not specify the correct payment amount");
					return true;
				}
				CAmount nTotalValue = ( nPrice * theOfferAccept.nQty );
				CAmount nTotalCommission = ( nCommission * theOfferAccept.nQty );
				int nOutPayment, nOutCommission;
				nOutPayment = FindOfferAcceptPayment(tx, nTotalValue);
				if(nOutPayment < 0)
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1108 - " + _("Offer payment does not pay enough according to the offer price");
					return true;
				}
				if(!myPriceOffer.vchLinkOffer.empty())
				{
					nOutCommission = FindOfferAcceptPayment(tx, nTotalCommission);
					if(nOutCommission < 0)
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1109 - " + _("Offer payment does not include enough commission to affiliate");
						return true;
					}
					CSyscoinAddress destaddy;
					if (!ExtractDestination(tx.vout[nOutPayment].scriptPubKey, payDest))
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1110 - " + _("Could not extract payment destination from scriptPubKey");
						return true;
					}
					destaddy = CSyscoinAddress(payDest);
					CSyscoinAddress commissionaddy;
					if (!ExtractDestination(tx.vout[nOutCommission].scriptPubKey, commissionDest))
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1111 - " + _("Could not extract commission destination from scriptPubKey");
						return true;
					}
					commissionaddy = CSyscoinAddress(commissionDest);
					CSyscoinAddress aliaslinkaddy;
					linkAlias.GetAddress(&aliaslinkaddy);
					if(aliaslinkaddy.ToString() != destaddy.ToString())
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1112 - " + _("Payment destination does not match merchant address");
						return true;
					}
					CSyscoinAddress aliasaddy;
					alias.GetAddress(&aliasaddy);
					if(aliasaddy.ToString() != commissionaddy.ToString())
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1113 - " + _("Commission destination does not match affiliate address");
						return true;
					}
				}
				else
				{
					CSyscoinAddress destaddy;
					if (!ExtractDestination(tx.vout[nOutPayment].scriptPubKey, payDest))
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1114 - " + _("Could not extract payment destination from scriptPubKey");
						return true;
					}
					destaddy = CSyscoinAddress(payDest);
					CSyscoinAddress aliasaddy;
					alias.GetAddress(&aliasaddy);
					if(aliasaddy.ToString() != destaddy.ToString())
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1115 - " + _("Payment destination does not match merchant address");
						return true;
					}
				}
			}
			// check that the script for the offer update is sent to the correct destination
			if (!ExtractDestination(tx.vout[nOut].scriptPubKey, dest))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1116 - " + _("Cannot extract destination from output script");
				return true;
			}
			CPubKey pubKey(alias.vchPubKey);
			CSyscoinAddress aliasaddy(pubKey.GetID());
			aliasDest = aliasaddy.Get();
			if(!(aliasDest == dest))
			{
				errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1117 - " + _("Payment address does not match merchant address");
				return true;
			}
			theOfferAccept.vchAcceptRand = vvchArgs[1];
			// decrease qty + increase # sold
			if(theOfferAccept.nQty <= 0)
				theOfferAccept.nQty = 1;
			theOffer.accept = theOfferAccept;
			if (!linkOffer.IsNull())
			{
				linkOffer.nHeight = nHeight;
				linkOffer.txHash = tx.GetHash();
				linkOffer.accept = theOfferAccept;
				linkOffer.PutToOfferList(offerVtxPos);
				if (!dontaddtodb && !pofferdb->WriteOffer(myPriceOffer.vchLinkOffer, offerVtxPos))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 4072 - " + _("Failed to write to offer link to DB");
					return true;
				}
			}
			if(!theOfferAccept.txExtId.IsNull())
			{
				if(pofferdb->ExistsOfferTx(theOfferAccept.txExtId) || pescrowdb->ExistsEscrowTx(theOfferAccept.txExtId))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1118 - " + _("BTC Transaction ID specified was already used to pay for an offer");
					return true;
				}
				if(!dontaddtodb && !pofferdb->WriteOfferTx(theOffer.vchOffer, theOfferAccept.txExtId))
				{
					errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1119 - " + _("Failed to BTC Transaction ID to DB");
					return error(errorMessage.c_str());
				}
			}

		}


		if(op == OP_OFFER_UPDATE)
		{
			// ensure the accept is null as this should just have the offer information and no accept information
			theOffer.accept.SetNull();
			// if the txn whitelist entry exists (meaning we want to remove or add)
			if(serializedOffer.linkWhitelist.entries.size() == 1)
			{
				// special case we use to remove all entries
				if(serializedOffer.linkWhitelist.entries[0].nDiscountPct == 127)
				{
					if(theOffer.linkWhitelist.entries.empty())
					{
						errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1120 - " + _("Whitelist is already empty");
					}
					else
						theOffer.linkWhitelist.SetNull();
				}
				// the stored offer has this entry meaning we want to remove this entry
				else if(theOffer.linkWhitelist.GetLinkEntryByHash(serializedOffer.linkWhitelist.entries[0].aliasLinkVchRand, entry))
				{
					theOffer.linkWhitelist.RemoveWhitelistEntry(serializedOffer.linkWhitelist.entries[0].aliasLinkVchRand);
				}
				// we want to add it to the whitelist
				else
				{
					if(!serializedOffer.linkWhitelist.entries[0].aliasLinkVchRand.empty())
					{
						if (GetTxOfAlias(serializedOffer.linkWhitelist.entries[0].aliasLinkVchRand, theAlias, aliasTx))
						{
							theOffer.linkWhitelist.PutWhitelistEntry(serializedOffer.linkWhitelist.entries[0]);
						}
						else
						{
							errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1121 - " + _("Cannot find the alias you are trying to offer affiliate list. It may be expired");
						}
					}
				}

			}
			// if this offer is linked to a parent update it with parent information
			if(!theOffer.vchLinkOffer.empty())
			{
				theOffer.nQty = linkOffer.nQty;
				theOffer.vchCert = linkOffer.vchCert;
				theOffer.paymentOptions = linkOffer.paymentOptions;
				theOffer.SetPrice(linkOffer.nPrice);
			}
		}
		theOffer.nHeight = nHeight;
		theOffer.txHash = tx.GetHash();
		theOffer.PutToOfferList(vtxPos);
		// write offer

		if (!dontaddtodb && !pofferdb->WriteOffer(vvchArgs[0], vtxPos))
		{
			errorMessage = "SYSCOIN_OFFER_CONSENSUS_ERROR: ERRCODE: 1123 - " + _("Failed to write to offer DB");
			return error(errorMessage.c_str());
		}

		// debug
		if (fDebug)
			LogPrintf( "CONNECTED OFFER: op=%s offer=%s title=%s qty=%u hash=%s height=%d\n",
				offerFromOp(op).c_str(),
				stringFromVch(vvchArgs[0]).c_str(),
				stringFromVch(theOffer.sTitle).c_str(),
				theOffer.nQty,
				tx.GetHash().ToString().c_str(),
				nHeight);
	}
	return true;
}

UniValue offernew(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() < 7 || params.size() > 13)
		throw runtime_error(
		"offernew <alias> <category> <title> <quantity> <price> <description> <currency> [cert. guid] [exclusive resell=1] [payment options=SYS] [geolocation=''] [safe search=Yes] [private='0']\n"
						"<alias> An alias you own.\n"
						"<category> category, 255 chars max.\n"
						"<title> title, 255 chars max.\n"
						"<quantity> quantity, > 0 or -1 for infinite\n"
						"<price> price in <currency>, > 0\n"
						"<description> description, 1 KB max.\n"
						"<currency> The currency code that you want your offer to be in ie: USD.\n"
						"<cert. guid> Set this to the guid of a certificate you wish to sell\n"
						"<exclusive resell> set to 1 if you only want those who control the affiliate's who are able to resell this offer via offerlink. Defaults to 1.\n"
						"<paymentOptions> 'SYS' to accept SYS only, 'BTC' for BTC only, 'ZEC' for zcash only, or a |-delimited string to accept multiple currencies (e.g. 'BTC|SYS' to accept BTC or SYS). Leave empty for default. Defaults to 'SYS'.\n"
						"<geolocation> set to your geolocation. Defaults to empty. \n"
						"<safe search> set to No if this offer should only show in the search when safe search is not selected. Defaults to Yes (offer shows with or without safe search selected in search lists).\n"
						"<private> set to 1 if this offer should be private not be searchable. Defaults to 0.\n"
						+ HelpRequiringPassphrase());
	// gather inputs
	float fPrice;
	bool bExclusiveResell = true;
	vector<unsigned char> vchAlias = vchFromValue(params[0]);

	CTransaction aliastx;
	CAliasIndex alias;
	const CWalletTx *wtxAliasIn = NULL;
	if (!GetTxOfAlias(vchAlias, alias, aliastx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1500 - " + _("Could not find an alias with this name"));
    if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1501 - " + _("This alias is not yours"));
    }
	wtxAliasIn = pwalletMain->GetWalletTx(aliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1502 - " + _("This alias is not in your wallet"));

	vector<unsigned char> vchCat = vchFromValue(params[1]);
	vector<unsigned char> vchTitle = vchFromValue(params[2]);
	vector<unsigned char> vchCurrency = vchFromValue(params[6]);
	vector<unsigned char> vchDesc;
	vector<unsigned char> vchCert;

	int nQty;

	try {
		nQty =  boost::lexical_cast<int>(params[3].get_str());
	} catch (std::exception &e) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1503 - " + _("Invalid quantity value, must be less than 4294967296 and greater than or equal to -1"));
	}
	fPrice = boost::lexical_cast<float>(params[4].get_str());
	vchDesc = vchFromValue(params[5]);
	CScript scriptPubKeyOrig;
	CScript scriptPubKey;
	if(params.size() >= 8)
	{

		vchCert = vchFromValue(params[7]);
		if(vchCert == vchFromString("nocert"))
			vchCert.clear();
	}

	if(params.size() >= 9)
	{
		bExclusiveResell = boost::lexical_cast<int>(params[8].get_str()) == 1? true: false;
	}

	// payment options - get payment options string if specified otherwise default to SYS
	string paymentOptions = "SYS";
	if(params.size() >= 10 && !params[9].get_str().empty() && params[9].get_str() != "NONE")
	{
		paymentOptions = params[9].get_str();
	}
	// payment options - validate payment options string
	if(!ValidatePaymentOptionsString(paymentOptions))
	{
		// TODO change error number to something unique
		string err = "SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1504 - " + _("Could not validate the payment options value");
		throw runtime_error(err.c_str());
	}
	// payment options - and convert payment options string to a bitmask for the txn
	unsigned char paymentOptionsMask = (unsigned char) GetPaymentOptionsMaskFromString(paymentOptions);

	string strGeoLocation = "";
	if(params.size() >= 11)
	{
		strGeoLocation = params[10].get_str();
	}
	string strSafeSearch = "Yes";
	if(params.size() >= 12)
	{
		strSafeSearch = params[11].get_str();
	}
	bool bPrivate = false;
	if (params.size() >= 13) bPrivate = boost::lexical_cast<int>(params[12].get_str()) == 1? true: false;

	int precision = 2;
	CAmount nPricePerUnit = convertCurrencyCodeToSyscoin(alias.vchAliasPeg, vchCurrency, fPrice, chainActive.Tip()->nHeight, precision);
	if(nPricePerUnit == 0)
	{
		string err = "SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1504 - " + _("Could not find currency in the peg alias");
		throw runtime_error(err.c_str());
	}

	// this is a syscoin transaction
	CWalletTx wtx;

	// generate rand identifier
	vector<unsigned char> vchOffer = vchFromString(GenerateSyscoinGuid());
	EnsureWalletIsUnlocked();


	// unserialize offer from txn, serialize back
	// build offer
	COffer newOffer;
	newOffer.vchAlias = alias.vchAlias;
	newOffer.vchOffer = vchOffer;
	newOffer.sCategory = vchCat;
	newOffer.sTitle = vchTitle;
	newOffer.sDescription = vchDesc;
	newOffer.nQty = nQty;
	newOffer.nHeight = chainActive.Tip()->nHeight;
	newOffer.SetPrice(nPricePerUnit);
	newOffer.vchCert = vchCert;
	newOffer.linkWhitelist.bExclusiveResell = bExclusiveResell;
	newOffer.sCurrencyCode = vchCurrency;
	newOffer.bPrivate = bPrivate;
	newOffer.paymentOptions = paymentOptionsMask;
	newOffer.safetyLevel = 0;
	newOffer.safeSearch = strSafeSearch == "Yes"? true: false;
	newOffer.vchGeoLocation = vchFromString(strGeoLocation);

	const vector<unsigned char> &data = newOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	CPubKey currentOfferKey(alias.vchPubKey);
	scriptPubKeyOrig= GetScriptForDestination(currentOfferKey.GetID());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_ACTIVATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyAlias;
	if(alias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(alias.multiSigInfo.vchRedeemScript.begin(), alias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << alias.vchAlias << alias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, alias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, alias.multiSigInfo.vchAliases.size() > 0);
	UniValue res(UniValue::VARR);
	if(alias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
			res.push_back(stringFromVch(vchOffer));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchOffer));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchOffer));
	}

	return res;
}

UniValue offerlink(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() < 3 || params.size() > 4)
		throw runtime_error(
		"offerlink <alias> <guid> <commission> [description]\n"
						"<alias> An alias you own.\n"
						"<guid> offer guid that you are linking to\n"
						"<commission> percentage of profit desired over original offer price, > 0, ie: 5 for 5%\n"
						"<description> description, 1 KB max. Defaults to original description. Leave as '' to use default.\n"
						+ HelpRequiringPassphrase());
	// gather inputs
	COfferLinkWhitelistEntry whiteListEntry;
	vector<unsigned char> vchAlias = vchFromValue(params[0]);


	CTransaction aliastx;
	CAliasIndex alias;
	const CWalletTx *wtxAliasIn = NULL;
	if (!GetTxOfAlias(vchAlias, alias, aliastx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1505 - " + _("Could not find an alias with this name"));
    if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1506 - " + _("This alias is not yours"));
    }
	wtxAliasIn = pwalletMain->GetWalletTx(aliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1507 - " + _("This alias is not in your wallet"));

	vector<unsigned char> vchLinkOffer = vchFromValue(params[1]);
	vector<unsigned char> vchDesc;
	// look for a transaction with this key
	CTransaction tx;
	COffer linkOffer;
	if (vchLinkOffer.empty() || !GetTxOfOffer( vchLinkOffer, linkOffer, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1508 - " + _("Could not find an offer with this guid"));

	int commissionInteger = boost::lexical_cast<int>(params[2].get_str());
	if(params.size() >= 4)
	{

		vchDesc = vchFromValue(params[3]);
		if(vchDesc.empty())
		{
			vchDesc = linkOffer.sDescription;
		}
	}
	else
	{
		vchDesc = linkOffer.sDescription;
	}

	CScript scriptPubKeyOrig;
	CScript scriptPubKey;

	// this is a syscoin transaction
	CWalletTx wtx;


	// generate rand identifier
	vector<unsigned char> vchOffer = vchFromString(GenerateSyscoinGuid());
	EnsureWalletIsUnlocked();

	// build offer
	COffer newOffer;
	newOffer.vchOffer = vchOffer;
	newOffer.vchAlias = alias.vchAlias;
	newOffer.sDescription = vchDesc;
	newOffer.SetPrice(linkOffer.GetPrice());
	newOffer.paymentOptions = linkOffer.paymentOptions;
	newOffer.nCommission = commissionInteger;
	newOffer.vchLinkOffer = vchLinkOffer;
	newOffer.nHeight = chainActive.Tip()->nHeight;
	//create offeractivate txn keys

	const vector<unsigned char> &data = newOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	CPubKey aliasKey(alias.vchPubKey);
	scriptPubKeyOrig = GetScriptForDestination(aliasKey.GetID());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_ACTIVATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyAlias;
	if(alias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(alias.multiSigInfo.vchRedeemScript.begin(), alias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << alias.vchAlias << alias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;


	string strError;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);


	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, alias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, alias.multiSigInfo.vchAliases.size() > 0);

	UniValue res(UniValue::VARR);
	if(alias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
			res.push_back(stringFromVch(vchOffer));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchOffer));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchOffer));
	}
	return res;
}

UniValue offeraddwhitelist(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() < 2 || params.size() > 3)
		throw runtime_error(
		"offeraddwhitelist <offer guid> <alias guid> [discount percentage]\n"
		"Add to the affiliate list of your offer(controls who can resell).\n"
						"<offer guid> offer guid that you are adding to\n"
						"<alias guid> alias guid representing an alias that you want to add to the affiliate list\n"
						"<discount percentage> percentage of discount given to affiliate for this offer. 0 to 99.\n"
						+ HelpRequiringPassphrase());

	// gather & validate inputs
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchAlias =  vchFromValue(params[1]);
	int nDiscountPctInteger = 0;

	if(params.size() >= 3)
		nDiscountPctInteger = boost::lexical_cast<int>(params[2].get_str());

	CWalletTx wtx;

	// this is a syscoin txn
	CScript scriptPubKeyOrig;
	// create OFFERUPDATE txn key
	CScript scriptPubKey;



	EnsureWalletIsUnlocked();

	// look for a transaction with this key
	CTransaction tx;
	COffer theOffer;
	if (!GetTxOfOffer( vchOffer, theOffer, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1509 - " + _("Could not find an offer with this guid"));

	CTransaction aliastx;
	CAliasIndex theAlias;
	const CWalletTx *wtxAliasIn = NULL;
	if (!GetTxOfAlias( theOffer.vchAlias, theAlias, aliastx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1510 - " + _("Could not find an alias with this guid"));

	if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1511 - " + _("This alias is not yours"));
	}
	wtxAliasIn = pwalletMain->GetWalletTx(aliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1512 - " + _("This alias is not in your wallet"));


	CPubKey currentKey(theAlias.vchPubKey);
	scriptPubKeyOrig = GetScriptForDestination(currentKey.GetID());


	COfferLinkWhitelistEntry foundEntry;
	if(theOffer.linkWhitelist.GetLinkEntryByHash(vchAlias, foundEntry))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1514 - " + _("This alias entry already exists on affiliate list"));

	COfferLinkWhitelistEntry entry;
	entry.aliasLinkVchRand = vchAlias;
	entry.nDiscountPct = nDiscountPctInteger;
	theOffer.ClearOffer();
	theOffer.vchAlias = theAlias.vchAlias;
	theOffer.linkWhitelist.PutWhitelistEntry(entry);
	theOffer.nHeight = chainActive.Tip()->nHeight;


	const vector<unsigned char> &data = theOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyAlias;
	if(theAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(theAlias.multiSigInfo.vchRedeemScript.begin(), theAlias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << theAlias.vchAlias << theAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, theAlias.multiSigInfo.vchAliases.size() > 0);

	UniValue res(UniValue::VARR);
	if(theAlias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
		}
		else
		{
			res.push_back(hex_str);
			res.push_back("false");
		}
	}
	else
		res.push_back(wtx.GetHash().GetHex());
	return res;
}
UniValue offerremovewhitelist(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() != 2)
		throw runtime_error(
		"offerremovewhitelist <offer guid> <alias guid>\n"
		"Remove from the affiliate list of your offer(controls who can resell).\n"
						+ HelpRequiringPassphrase());
	// gather & validate inputs
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchAlias = vchFromValue(params[1]);

	CTransaction txCert;
	CCert theCert;
	CWalletTx wtx;

	// this is a syscoin txn
	CScript scriptPubKeyOrig;
	// create OFFERUPDATE txn keys
	CScript scriptPubKey;

	EnsureWalletIsUnlocked();

	// look for a transaction with this key
	CTransaction tx;
	COffer theOffer;
	const CWalletTx *wtxAliasIn = NULL;
	if (!GetTxOfOffer( vchOffer, theOffer, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1515 - " + _("Could not find an offer with this guid"));
	CTransaction aliastx;
	CAliasIndex theAlias;
	if (!GetTxOfAlias( theOffer.vchAlias, theAlias, aliastx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1516 - " + _("Could not find an alias with this guid"));
	if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1517 - " + _("This alias is not yours"));
	}
	wtxAliasIn = pwalletMain->GetWalletTx(aliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1518 - " + _("This alias is not in your wallet"));

	CPubKey currentKey(theAlias.vchPubKey);
	scriptPubKeyOrig = GetScriptForDestination(currentKey.GetID());

	// create OFFERUPDATE txn keys
	COfferLinkWhitelistEntry foundEntry;
	if(!theOffer.linkWhitelist.GetLinkEntryByHash(vchAlias, foundEntry))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1520 - " + _("This alias entry was not found on affiliate list"));
	theOffer.ClearOffer();
	theOffer.vchAlias = theAlias.vchAlias;
	theOffer.nHeight = chainActive.Tip()->nHeight;
	theOffer.linkWhitelist.PutWhitelistEntry(foundEntry);

	const vector<unsigned char> &data = theOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyAlias;
	if(theAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(theAlias.multiSigInfo.vchRedeemScript.begin(), theAlias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << theAlias.vchAlias << theAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, theAlias.multiSigInfo.vchAliases.size() > 0);

	UniValue res(UniValue::VARR);
	if(theAlias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
		}
		else
		{
			res.push_back(hex_str);
			res.push_back("false");
		}
	}
	else
		res.push_back(wtx.GetHash().GetHex());
	return res;
}
UniValue offerclearwhitelist(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() != 1)
		throw runtime_error(
		"offerclearwhitelist <offer guid>\n"
		"Clear the affiliate list of your offer(controls who can resell).\n"
						+ HelpRequiringPassphrase());
	// gather & validate inputs
	vector<unsigned char> vchOffer = vchFromValue(params[0]);

	// this is a syscoind txn
	CWalletTx wtx;
	CScript scriptPubKeyOrig;

	EnsureWalletIsUnlocked();

	// look for a transaction with this key
	CTransaction tx;
	COffer theOffer;
	const CWalletTx *wtxAliasIn = NULL;
	if (!GetTxOfOffer( vchOffer, theOffer, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1521 - " + _("Could not find an offer with this guid"));
	CTransaction aliastx;
	CAliasIndex theAlias;
	if (!GetTxOfAlias(theOffer.vchAlias, theAlias, aliastx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1522 - " + _("Could not find an alias with this guid"));

	if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1523 - " + _("This alias is not yours"));
	}
	wtxAliasIn = pwalletMain->GetWalletTx(aliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1524 - " + _("This alias is not in your wallet"));

	CPubKey currentKey(theAlias.vchPubKey);
	scriptPubKeyOrig = GetScriptForDestination(currentKey.GetID());

	theOffer.ClearOffer();
	theOffer.vchAlias = theAlias.vchAlias;
	theOffer.nHeight = chainActive.Tip()->nHeight;
	// create OFFERUPDATE txn keys
	CScript scriptPubKey;

	COfferLinkWhitelistEntry entry;
	// special case to clear all entries for this offer
	entry.nDiscountPct = 127;
	theOffer.linkWhitelist.PutWhitelistEntry(entry);

	const vector<unsigned char> &data = theOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyAlias;
	if(theAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(theAlias.multiSigInfo.vchRedeemScript.begin(), theAlias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << theAlias.vchAlias << theAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, theAlias.multiSigInfo.vchAliases.size() > 0);

	UniValue res(UniValue::VARR);
	if(theAlias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
		}
		else
		{
			res.push_back(hex_str);
			res.push_back("false");
		}
	}
	else
		res.push_back(wtx.GetHash().GetHex());
	return res;
}

UniValue offerwhitelist(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("offerwhitelist <offer guid>\n"
                "List all affiliates for this offer.\n");
    UniValue oRes(UniValue::VARR);
    vector<unsigned char> vchOffer = vchFromValue(params[0]);
	// look for a transaction with this key
	CTransaction tx;
	COffer theOffer;
	vector<COffer> myVtxPos;
	if (!GetTxAndVtxOfOffer( vchOffer, theOffer, tx, myVtxPos))
		throw runtime_error("could not find an offer with this guid");

	for(unsigned int i=0;i<theOffer.linkWhitelist.entries.size();i++) {
		CTransaction txAlias;
		CAliasIndex theAlias;
		COfferLinkWhitelistEntry& entry = theOffer.linkWhitelist.entries[i];
		if (GetTxOfAlias(entry.aliasLinkVchRand, theAlias, txAlias))
		{
			UniValue oList(UniValue::VOBJ);
			oList.push_back(Pair("alias", stringFromVch(entry.aliasLinkVchRand)));
			int expires_in = 0;
			uint64_t nHeight = theAlias.nHeight;
			if (!GetSyscoinTransaction(nHeight, txAlias.GetHash(), txAlias, Params().GetConsensus()))
				continue;

            if(nHeight + (theAlias.nRenewal*GetAliasExpirationDepth()) - chainActive.Tip()->nHeight > 0)
			{
				expires_in = nHeight + (theAlias.nRenewal*GetAliasExpirationDepth()) - chainActive.Tip()->nHeight;
			}
			oList.push_back(Pair("expiresin",expires_in));
			oList.push_back(Pair("offer_discount_percentage", strprintf("%d%%", entry.nDiscountPct)));
			oRes.push_back(oList);
		}
    }
    return oRes;
}
UniValue offerupdate(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() < 6 || params.size() > 15)
		throw runtime_error(
		"offerupdate <alias> <guid> <category> <title> <quantity> <price> [description] [currency] [private='0'] [cert. guid=''] [exclusive resell='1'] [geolocation=''] [safesearch=Yes] [commission=0] [paymentOptions=0]\n"
						"Perform an update on an offer you control.\n"
						+ HelpRequiringPassphrase());
	// gather & validate inputs
	vector<unsigned char> vchAlias = vchFromValue(params[0]);
	vector<unsigned char> vchOffer = vchFromValue(params[1]);
	vector<unsigned char> vchCat = vchFromValue(params[2]);
	vector<unsigned char> vchTitle = vchFromValue(params[3]);
	vector<unsigned char> vchDesc;
	vector<unsigned char> vchCert;
	vector<unsigned char> vchGeoLocation;
	vector<unsigned char> sCurrencyCode;
	bool bExclusiveResell = true;
	int bPrivate = false;
	int nQty;
	float fPrice;
	int nCommission = 0;
	if (params.size() >= 7) vchDesc = vchFromValue(params[6]);
	if (params.size() >= 8) sCurrencyCode = vchFromValue(params[7]);
	if (params.size() >= 9) bPrivate = boost::lexical_cast<int>(params[8].get_str()) == 1? true: false;
	if (params.size() >= 10) vchCert = vchFromValue(params[9]);
	if(vchCert == vchFromString("nocert"))
		vchCert.clear();
	if (params.size() >= 11) bExclusiveResell = boost::lexical_cast<int>(params[10].get_str()) == 1? true: false;
	if (params.size() >= 12) vchGeoLocation = vchFromValue(params[11]);
	string strSafeSearch = "Yes";
	if(params.size() >= 13)
	{
		strSafeSearch = params[12].get_str();
	}
	if(params.size() >= 14 && !params[13].get_str().empty() && params[13].get_str() != "NONE")
	{
		nCommission = boost::lexical_cast<int>(params[13].get_str());
	}

	string paymentOptions = "SYS";
	if(params.size() >= 15 && !params[14].get_str().empty() && params[14].get_str() != "NONE")
	{
		paymentOptions = params[14].get_str();
	}
	if(!ValidatePaymentOptionsString(paymentOptions))
	{
		//TODO change the errcode to something unique
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1527 - " + _("Could not validate payment options string"));
	}
	unsigned char paymentOptionsMask = (unsigned char) GetPaymentOptionsMaskFromString(paymentOptions);

	try {
		nQty = boost::lexical_cast<int>(params[4].get_str());
		fPrice = boost::lexical_cast<float>(params[5].get_str());

	} catch (std::exception &e) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1526 - " + _("Invalid price and/or quantity values. Quantity must be less than 4294967296 and greater than or equal to -1"));
	}

	CAliasIndex alias;
	CTransaction aliastx;
	const CWalletTx *wtxAliasIn = NULL;

	// this is a syscoind txn
	CWalletTx wtx;
	CScript scriptPubKeyOrig, scriptPubKeyCertOrig;

	EnsureWalletIsUnlocked();

	// look for a transaction with this key
	CTransaction tx, linktx;
	COffer theOffer, linkOffer;
	if (!GetTxOfOffer( vchOffer, theOffer, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1527 - " + _("Could not find an offer with this guid"));

	if (!GetTxOfAlias(theOffer.vchAlias, alias, aliastx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1528 - " + _("Could not find an alias with this name"));

	if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1529 - " + _("This alias is not yours"));
	}
	wtxAliasIn = pwalletMain->GetWalletTx(aliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1530 - " + _("This alias is not in your wallet"));

	CPubKey currentKey(alias.vchPubKey);
	scriptPubKeyOrig = GetScriptForDestination(currentKey.GetID());

	// create OFFERUPDATE, ALIASUPDATE txn keys
	CScript scriptPubKey;

	COffer offerCopy = theOffer;
	theOffer.ClearOffer();
	theOffer.nHeight = chainActive.Tip()->nHeight;
	if(offerCopy.sCategory != vchCat)
		theOffer.sCategory = vchCat;
	if(offerCopy.sTitle != vchTitle)
		theOffer.sTitle = vchTitle;
	if(offerCopy.sDescription != vchDesc)
		theOffer.sDescription = vchDesc;
	if(offerCopy.vchGeoLocation != vchGeoLocation)
		theOffer.vchGeoLocation = vchGeoLocation;
	CAmount nPricePerUnit = offerCopy.GetPrice();
	if(sCurrencyCode.empty() || sCurrencyCode == vchFromString("NONE"))
		sCurrencyCode = offerCopy.sCurrencyCode;
	if(offerCopy.sCurrencyCode != sCurrencyCode)
		theOffer.sCurrencyCode = sCurrencyCode;

	// linked offers can't change these settings, they are overrided by parent info
	if(offerCopy.vchLinkOffer.empty())
	{
		if(offerCopy.vchCert != vchCert)
			theOffer.vchCert = vchCert;
		int precision = 2;
		nPricePerUnit = convertCurrencyCodeToSyscoin(alias.vchAliasPeg, sCurrencyCode, fPrice, chainActive.Tip()->nHeight, precision);
		if(nPricePerUnit == 0)
		{
			string err = "SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1532 - " + _("Could not find currency in the peg alias");
			throw runtime_error(err.c_str());
		}
	}
	if(params.size() >= 14 && !params[13].get_str().empty() && params[13].get_str() != "NONE")
		theOffer.nCommission = nCommission;
	if(params.size() >= 15 && !params[14].get_str().empty() && params[14].get_str() != "NONE")
		theOffer.paymentOptions = paymentOptionsMask;

	theOffer.vchAlias = alias.vchAlias;
	if(!vchAlias.empty() && vchAlias != alias.vchAlias)
		theOffer.vchLinkAlias = vchAlias;
	theOffer.safeSearch = strSafeSearch == "Yes"? true: false;
	theOffer.nQty = nQty;
	if (params.size() >= 9)
		theOffer.bPrivate = bPrivate;

	theOffer.nHeight = chainActive.Tip()->nHeight;
	theOffer.SetPrice(nPricePerUnit);
	if(params.size() >= 11 && params[10].get_str().size() > 0)
		theOffer.linkWhitelist.bExclusiveResell = bExclusiveResell;
	else
		theOffer.linkWhitelist.bExclusiveResell = offerCopy.linkWhitelist.bExclusiveResell;



	const vector<unsigned char> &data = theOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CScript scriptPubKeyAlias;
	if(alias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(alias.multiSigInfo.vchRedeemScript.begin(), alias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << alias.vchAlias << alias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);


	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, alias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneySyscoin(vecSend, recipient.nAmount+aliasRecipient.nAmount+fee.nAmount, false, wtx, wtxAliasIn, alias.multiSigInfo.vchAliases.size() > 0);
	UniValue res(UniValue::VARR);
	if(alias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
		}
		else
		{
			res.push_back(hex_str);
			res.push_back("false");
		}
	}
	else
		res.push_back(wtx.GetHash().GetHex());
	return res;
}
UniValue offeraccept(const UniValue& params, bool fHelp) {
	if (fHelp || 1 > params.size() || params.size() > 6)
		throw runtime_error("offeraccept <alias> <guid> [quantity] [message] [Ext TxId] [payment option=SYS]\n"
				"Accept&Pay for a confirmed offer.\n"
				"<alias> An alias of the buyer.\n"
				"<guid> guidkey from offer.\n"
				"<quantity> quantity to buy. Defaults to 1.\n"
				"<message> payment message to seller, 1KB max.\n"
				"<Ext TxId> If paid in another coin, enter the Transaction ID here. Default is empty.\n"
				"<paymentOption> If Ext TxId is defined, specify a valid payment option used to make payment. Default is SYS.\n"
				+ HelpRequiringPassphrase());
	CSyscoinAddress refundAddr;
	vector<unsigned char> vchAlias = vchFromValue(params[0]);
	vector<unsigned char> vchOffer = vchFromValue(params[1]);
	vector<unsigned char> vchExtTxId = vchFromValue(params.size()>=5?params[4]:"");

	vector<unsigned char> vchMessage = vchFromValue(params.size()>=4?params[3]:"");
	int64_t nHeight = chainActive.Tip()->nHeight;
	unsigned int nQty = 1;
	if (params.size() >= 3) {
		try {
			nQty = boost::lexical_cast<unsigned int>(params[2].get_str());
		} catch (std::exception &e) {
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1534 - " + _("Quantity must be less than 4294967296"));
		}
	}
	// payment options - get payment options string if specified otherwise default to SYS
	string paymentOptions = "SYS";
	if(params.size() >= 6 && !params[5].get_str().empty() && params[5].get_str() != "NONE")
	{
		paymentOptions = params[5].get_str();
	}
	// payment options - validate payment options string
	if(!ValidatePaymentOptionsString(paymentOptions))
	{
		// TODO change error number to something unique
		string err = "SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1504 - " + _("Could not validate the payment options value");
		throw runtime_error(err.c_str());
	}
		// payment options - and convert payment options string to a bitmask for the txn
	unsigned char paymentOptionsMask = (unsigned char) GetPaymentOptionsMaskFromString(paymentOptions);
	// this is a syscoin txn
	CWalletTx wtx;
	CScript scriptPubKeyAliasOrig;
	vector<unsigned char> vchAccept = vchFromString(GenerateSyscoinGuid());

	// create OFFERACCEPT txn keys
	CScript scriptPubKeyAccept, scriptPubKeyPayment;
	CScript scriptPubKeyAlias;
	EnsureWalletIsUnlocked();
	CTransaction acceptTx;
	COffer theOffer;
	// if this is a linked offer accept, set the height to the first height so sysrates.peg price will match what it was at the time of the original accept
	CTransaction tx;
	vector<COffer> vtxPos;
	if (!GetTxAndVtxOfOffer( vchOffer, theOffer, tx, vtxPos, true))
	{
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1535 - " + _("Could not find an offer with this identifier"));
	}

	COffer linkOffer;
	CTransaction linkedTx;
	vector<COffer> vtxLinkPos;
	GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, linkedTx, vtxLinkPos, true);

	CTransaction aliastx,buyeraliastx;
	CAliasIndex theAlias,tmpAlias;
	bool isExpired = false;
	vector<CAliasIndex> aliasVtxPos;
	if(!GetTxAndVtxOfAlias(theOffer.vchAlias, theAlias, aliastx, aliasVtxPos, isExpired, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1536 - " + _("Could not find the alias associated with this offer"));

	CAliasIndex buyerAlias;
	if (!GetTxOfAlias(vchAlias, buyerAlias, buyeraliastx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1537 - " + _("Could not find buyer alias with this name"));

	const CWalletTx *wtxAliasIn = NULL;
	COfferLinkWhitelistEntry foundEntry;
	CAmount nPrice;
	CAmount nCommission;
	if(theOffer.vchLinkOffer.empty())
	{
		theOffer.linkWhitelist.GetLinkEntryByHash(buyerAlias.vchAlias, foundEntry);
		nPrice = theOffer.GetPrice(foundEntry);
		nCommission = 0;
	}
	else
	{
		linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, foundEntry);
		nPrice = linkOffer.GetPrice(foundEntry);
		nCommission = theOffer.GetPrice() - nPrice;
	}
	wtxAliasIn = pwalletMain->GetWalletTx(buyeraliastx.GetHash());
	CPubKey currentKey(buyerAlias.vchPubKey);
	scriptPubKeyAliasOrig = GetScriptForDestination(currentKey.GetID());
	if(buyerAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyAliasOrig = CScript(buyerAlias.multiSigInfo.vchRedeemScript.begin(), buyerAlias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << buyerAlias.vchAlias  << buyerAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyAliasOrig;

	string strCipherText = "";

	CAliasIndex theLinkedAlias;
	if(!theOffer.vchLinkOffer.empty())
	{
		if (!GetTxOfAlias(linkOffer.vchAlias, theLinkedAlias, aliastx, true))
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1539 - " + _("Could not find an alias with this guid"));

		// encrypt to root offer owner if this is a linked offer you are accepting
		if(!EncryptMessage(theLinkedAlias.vchPubKey, vchMessage, strCipherText))
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1540 - " + _("Could not encrypt message to seller"));
	}
	else
	{
		// encrypt to offer owner
		if(!EncryptMessage(theAlias.vchPubKey, vchMessage, strCipherText))
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1541 - " + _("Could not encrypt message to seller"));
	}

	vector<unsigned char> vchPaymentMessage = vchFromString(strCipherText);
	COfferAccept txAccept;
	txAccept.vchAcceptRand = vchAccept;
	txAccept.nQty = nQty;
	txAccept.nPrice = nPrice;
	// We need to do this to make sure we convert price at the time of initial buyer's accept.
	txAccept.nAcceptHeight = nHeight;
	txAccept.vchBuyerAlias = vchAlias;
	txAccept.vchMessage = vchPaymentMessage;
	txAccept.nPaymentOption = paymentOptionsMask;
    CAmount nTotalValue = ( nPrice * nQty );
	CAmount nTotalCommission = ( nCommission * nQty );
	if(!vchExtTxId.empty())
	{
		uint256 txExtId(uint256S(stringFromVch(vchExtTxId)));
		txAccept.txExtId = txExtId;
	}
	COffer copyOffer = theOffer;
	theOffer.ClearOffer();
	theOffer.accept = txAccept;
	theOffer.nHeight = chainActive.Tip()->nHeight;

	const vector<unsigned char> &data = theOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());

    CScript scriptPayment, scriptPubKeyCommission, scriptPubKeyOrig, scriptPubLinkKeyOrig, scriptPaymentCommission;
	currentKey = CPubKey(theAlias.vchPubKey);
	CSyscoinAddress currentAddress(currentKey.GetID());
	scriptPubKeyOrig = 	 GetScriptForDestination(currentAddress.Get());
	if(theAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(theAlias.multiSigInfo.vchRedeemScript.begin(), theAlias.multiSigInfo.vchRedeemScript.end());

	CPubKey currentLinkKey(theLinkedAlias.vchPubKey);
	CSyscoinAddress linkAddress(currentLinkKey.GetID());
	scriptPubLinkKeyOrig = GetScriptForDestination(linkAddress.Get());
	if(theLinkedAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubLinkKeyOrig = CScript(theLinkedAlias.multiSigInfo.vchRedeemScript.begin(), theLinkedAlias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAccept << CScript::EncodeOP_N(OP_OFFER_ACCEPT) << vchOffer << vchAccept << vchFromString("0") << vchHashOffer << OP_2DROP << OP_2DROP << OP_DROP;
	if(!copyOffer.vchLinkOffer.empty())
	{
		scriptPayment = scriptPubLinkKeyOrig;
		scriptPaymentCommission = scriptPubKeyOrig;
	}
	else
	{
		scriptPayment = scriptPubKeyOrig;
	}
	currentAddress = CSyscoinAddress(currentKey.GetID());
	scriptPubKeyAccept += GetScriptForDestination(currentAddress.Get());
	scriptPubKeyPayment += scriptPayment;
	scriptPubKeyCommission += scriptPaymentCommission;




	vector<CRecipient> vecSend;


	CRecipient acceptRecipient;
	CreateRecipient(scriptPubKeyAccept, acceptRecipient);
	CRecipient paymentRecipient = {scriptPubKeyPayment, nTotalValue, false};
	CRecipient paymentCommissionRecipient = {scriptPubKeyCommission, nTotalCommission, false};
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);


	if(vchExtTxId.empty())
	{
		vecSend.push_back(paymentRecipient);
		vecSend.push_back(acceptRecipient);
		if(!copyOffer.vchLinkOffer.empty())
			vecSend.push_back(paymentCommissionRecipient);
	}
	else
		vecSend.push_back(acceptRecipient);


	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, buyerAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);

	SendMoneySyscoin(vecSend, acceptRecipient.nAmount+paymentRecipient.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, buyerAlias.multiSigInfo.vchAliases.size() > 0);

	UniValue res(UniValue::VARR);
	if(buyerAlias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
			res.push_back(stringFromVch(vchAccept));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchAccept));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchAccept));
	}

	return res;
}

void HandleAcceptFeedback(const CFeedback& feedback, COffer& offer, vector<COffer> &vtxPos)
{
	if(feedback.nRating > 0)
	{
		string aliasStr;
		CPubKey key;
		if(feedback.nFeedbackUserTo == FEEDBACKBUYER)
			aliasStr = stringFromVch(offer.accept.vchBuyerAlias);
		else if(feedback.nFeedbackUserTo == FEEDBACKSELLER)
			aliasStr = stringFromVch(offer.vchAlias);
		CSyscoinAddress address = CSyscoinAddress(aliasStr);
		if(address.IsValid() && address.isAlias)
		{
			vector<CAliasIndex> vtxPos;
			const vector<unsigned char> &vchAlias = vchFromString(address.aliasName);
			if (paliasdb->ReadAlias(vchAlias, vtxPos) && !vtxPos.empty())
			{

				CAliasIndex alias = vtxPos.back();
				if(feedback.nFeedbackUserTo == FEEDBACKBUYER)
				{
					alias.nRatingCountAsBuyer++;
					alias.nRatingAsBuyer += feedback.nRating;
				}
				else if(feedback.nFeedbackUserTo == FEEDBACKSELLER)
				{
					alias.nRatingCountAsSeller++;
					alias.nRatingAsSeller += feedback.nRating;
				}
				else if(feedback.nFeedbackUserTo == FEEDBACKARBITER)
				{
					alias.nRatingCountAsArbiter++;
					alias.nRatingAsArbiter += feedback.nRating;
				}
				PutToAliasList(vtxPos, alias);
				CSyscoinAddress multisigAddress;
				alias.GetAddress(&multisigAddress);
				paliasdb->WriteAlias(vchAlias, vchFromString(address.ToString()), vchFromString(multisigAddress.ToString()), vtxPos);
			}
		}
	}
	offer.accept.feedback.push_back(feedback);
	offer.PutToOfferList(vtxPos);
	pofferdb->WriteOffer(offer.vchOffer, vtxPos);
}
void FindFeedback(const vector<CFeedback> &feedback, int &numBuyerRatings, int &numSellerRatings,int &numArbiterRatings, int &feedbackBuyerCount, int &feedbackSellerCount, int &feedbackArbiterCount)
{
	feedbackSellerCount = feedbackBuyerCount = feedbackArbiterCount = numBuyerRatings = numSellerRatings = numArbiterRatings = 0;
	for(unsigned int i =0;i<feedback.size();i++)
	{
		if(!feedback[i].IsNull())
		{
			if(feedback[i].nFeedbackUserFrom == FEEDBACKBUYER)
			{
				feedbackBuyerCount++;
				if(feedback[i].nRating > 0)
					numBuyerRatings++;
			}
			else if(feedback[i].nFeedbackUserFrom == FEEDBACKSELLER)
			{
				feedbackSellerCount++;
				if(feedback[i].nRating > 0)
					numSellerRatings++;
			}
			else if(feedback[i].nFeedbackUserFrom == FEEDBACKARBITER)
			{
				feedbackArbiterCount++;
				if(feedback[i].nRating > 0)
					numArbiterRatings++;
			}
		}
	}
}
void GetFeedback(vector<CFeedback> &feedBackSorted, int &avgRating, const FeedbackUser type, const vector<CFeedback>& feedBack)
{
	float nRating = 0;
	int nRatingCount = 0;
	for(unsigned int i =0;i<feedBack.size();i++)
	{
		if(!feedBack[i].IsNull() && feedBack[i].nFeedbackUserTo == type)
		{
			if(feedBack[i].nRating > 0)
			{
				nRating += feedBack[i].nRating;
				nRatingCount++;
			}
			feedBackSorted.push_back(feedBack[i]);
		}
	}
	if(nRatingCount > 0)
	{
		nRating /= nRatingCount;
	}
	avgRating = (int)roundf(nRating);
	if(feedBackSorted.size() > 0)
		sort(feedBackSorted.begin(), feedBackSorted.end(), feedbacksort());

}

UniValue offeracceptfeedback(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 4)
        throw runtime_error(
		"offeracceptfeedback <offer guid> <offeraccept guid> [feedback] [rating] \n"
                        "Send feedback and rating for offer accept specified. Ratings are numbers from 1 to 5\n"
                        + HelpRequiringPassphrase());
   // gather & validate inputs
	int nRating = 0;
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchAcceptRand = vchFromValue(params[1]);
	vector<unsigned char> vchFeedback = vchFromValue(params[2]);
	try {
		nRating = boost::lexical_cast<int>(params[3].get_str());
		if(nRating < 0 || nRating > 5)
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1542 - " + _("Invalid rating value, must be less than or equal to 5 and greater than or equal to 0"));

	} catch (std::exception &e) {
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1543 - " + _("Invalid rating value"));
	}


    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	COffer theOffer;
	COfferAccept theOfferAccept;
	const CWalletTx *wtxAliasIn = NULL;

	if (!GetTxOfOffer( vchOffer, theOffer, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1508 - " + _("Could not find an offer with this guid"));
	if(!theOffer.vchLinkOffer.empty())
	{
		if (!GetTxOfOffer( theOffer.vchLinkOffer, theOffer, tx, true))
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1508 - " + _("Could not find a linked offer with this guid"));
	}

	COffer tmpOffer;
	if (!GetTxOfOfferAccept(theOffer.vchOffer, vchAcceptRand, tmpOffer, theOfferAccept, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1544 - " + _("Could not find this offer purchase"));


	CAliasIndex buyerAlias, sellerAlias;
	CTransaction buyeraliastx, selleraliastx;

	GetTxOfAlias(theOfferAccept.vchBuyerAlias, buyerAlias, buyeraliastx, true);
	CPubKey buyerKey(buyerAlias.vchPubKey);
	CSyscoinAddress buyerAddress(buyerKey.GetID());

	GetTxOfAlias(theOffer.vchAlias, sellerAlias, selleraliastx, true);
	CPubKey sellerKey(sellerAlias.vchPubKey);
	CSyscoinAddress sellerAddress(sellerKey.GetID());

	CScript scriptPubKeyAlias;
	CScript scriptPubKey,scriptPubKeyOrig;
	vector<unsigned char> vchLinkAlias;
	CAliasIndex theAlias;
	bool foundBuyerKey = false;
	bool foundSellerKey = false;
	try
	{
		CKeyID keyID;
		if (!buyerAddress.GetKeyID(keyID))
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1546 - " + _("Buyer address does not refer to a key"));
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1547 - " + _("Private key for buyer address is not known"));
		vchLinkAlias = buyerAlias.vchAlias;
		theAlias = buyerAlias;
		foundBuyerKey = true;
	}
	catch(...)
	{
		foundBuyerKey = false;
	}

	try
	{
		CKeyID keyID;
		if (!sellerAddress.GetKeyID(keyID))
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1548 - " + _("Seller address does not refer to a key"));
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1549 - " + _("Private key for seller address is not known"));
		vchLinkAlias = sellerAlias.vchAlias;
		theAlias = sellerAlias;
		foundSellerKey = true;
		foundBuyerKey = false;
	}
	catch(...)
	{
		foundSellerKey = false;
	}

	theOffer.ClearOffer();
	theOffer.accept = theOfferAccept;
	theOffer.accept.vchBuyerAlias = vchLinkAlias;
	theOffer.accept.bPaymentAck = false;
	theOffer.nHeight = chainActive.Tip()->nHeight;
	// buyer
	if(foundBuyerKey)
	{
		CFeedback sellerFeedback(FEEDBACKBUYER, FEEDBACKSELLER);
		sellerFeedback.vchFeedback = vchFeedback;
		sellerFeedback.nRating = nRating;
		sellerFeedback.nHeight = chainActive.Tip()->nHeight;
		theOffer.accept.feedback.clear();
		theOffer.accept.feedback.push_back(sellerFeedback);
		wtxAliasIn = pwalletMain->GetWalletTx(buyeraliastx.GetHash());
		if (wtxAliasIn == NULL)
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1550 - " + _("Buyer alias is not in your wallet"));

		scriptPubKeyOrig= GetScriptForDestination(buyerKey.GetID());
		if(buyerAlias.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyOrig = CScript(buyerAlias.multiSigInfo.vchRedeemScript.begin(), buyerAlias.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << buyerAlias.vchAlias << buyerAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyOrig;
		scriptPubKeyOrig= GetScriptForDestination(sellerKey.GetID());
	}
	// seller
	else if(foundSellerKey)
	{
		CFeedback buyerFeedback(FEEDBACKSELLER, FEEDBACKBUYER);
		buyerFeedback.vchFeedback = vchFeedback;
		buyerFeedback.nRating = nRating;
		buyerFeedback.nHeight = chainActive.Tip()->nHeight;
		theOffer.accept.feedback.clear();
		theOffer.accept.feedback.push_back(buyerFeedback);
		wtxAliasIn = pwalletMain->GetWalletTx(selleraliastx.GetHash());
		if (wtxAliasIn == NULL)
			throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1551 - " + _("Seller alias is not in your wallet"));

		scriptPubKeyOrig= GetScriptForDestination(sellerKey.GetID());
		if(sellerAlias.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyOrig = CScript(sellerAlias.multiSigInfo.vchRedeemScript.begin(), sellerAlias.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias = CScript() <<  CScript::EncodeOP_N(OP_ALIAS_UPDATE) << sellerAlias.vchAlias << sellerAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyOrig;
		scriptPubKeyOrig= GetScriptForDestination(buyerKey.GetID());

	}
	else
	{
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1552 - " + _("You must be either the buyer or seller to leave feedback on this offer purchase"));
	}

	const vector<unsigned char> &data = theOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());

	vector<CRecipient> vecSend;
	CRecipient recipientAlias, recipient;


	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_ACCEPT) << theOffer.vchOffer << theOfferAccept.vchAcceptRand << vchFromString("1") << vchHashOffer << OP_2DROP <<  OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CreateRecipient(scriptPubKey, recipient);
	CreateRecipient(scriptPubKeyAlias, recipientAlias);

	vecSend.push_back(recipient);
	vecSend.push_back(recipientAlias);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneySyscoin(vecSend, recipient.nAmount+recipientAlias.nAmount+fee.nAmount, false, wtx, wtxAliasIn, theAlias.multiSigInfo.vchAliases.size() > 0);
	UniValue res(UniValue::VARR);
	if(theAlias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
		}
		else
		{
			res.push_back(hex_str);
			res.push_back("false");
		}
	}
	else
		res.push_back(wtx.GetHash().GetHex());
	return res;
}
UniValue offeracceptacknowledge(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
		"offeracceptacknowledge <offer guid> <offeraccept guid> \n"
                        "Acknowledge offer payment as seller of offer. Deducts qty of offer and increases number of sold inventory.\n"
                        + HelpRequiringPassphrase());
   // gather & validate inputs
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchAcceptRand = vchFromValue(params[1]);

    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	COffer theOffer;
	COfferAccept theOfferAccept;
	const CWalletTx *wtxAliasIn = NULL;

	if (!GetTxOfOffer( vchOffer, theOffer, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1508 - " + _("Could not find an offer with this guid"));

	COffer tmpOffer;
	if (!GetTxOfOfferAccept(theOffer.vchOffer, vchAcceptRand, tmpOffer, theOfferAccept, tx, true))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1544 - " + _("Could not find this offer purchase"));


	CAliasIndex buyerAlias, sellerAlias;
	CTransaction buyeraliastx, selleraliastx;

	GetTxOfAlias(theOfferAccept.vchBuyerAlias, buyerAlias, buyeraliastx, true);
	CPubKey buyerKey(buyerAlias.vchPubKey);
	CSyscoinAddress buyerAddress(buyerKey.GetID());

	GetTxOfAlias(theOffer.vchAlias, sellerAlias, selleraliastx, true);
	CPubKey sellerKey(sellerAlias.vchPubKey);
	CSyscoinAddress sellerAddress(sellerKey.GetID());

	CScript scriptPubKeyAlias;
	CScript scriptPubKey,scriptPubKeyBuyer, scriptPubKeyOrig, scriptPubKeyBuyerOrig;

	CKeyID keyID;
	if (!sellerAddress.GetKeyID(keyID))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1548 - " + _("Seller address does not refer to a key"));
	CKey vchSecret;
	if (!pwalletMain->GetKey(keyID, vchSecret))
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1549 - " + _("Private key for seller address is not known"));



	theOffer.ClearOffer();
	theOffer.accept.bPaymentAck = true;
	theOffer.accept.vchBuyerAlias = sellerAlias.vchAlias;
	theOffer.accept.nPaymentOption = theOfferAccept.nPaymentOption;
	theOffer.nHeight = chainActive.Tip()->nHeight;

	wtxAliasIn = pwalletMain->GetWalletTx(selleraliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("SYSCOIN_OFFER_RPC_ERROR ERRCODE: 1551 - " + _("Seller alias is not in your wallet"));

	scriptPubKeyOrig= GetScriptForDestination(sellerKey.GetID());
	if(sellerAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(sellerAlias.multiSigInfo.vchRedeemScript.begin(), sellerAlias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias = CScript() <<  CScript::EncodeOP_N(OP_ALIAS_UPDATE) << sellerAlias.vchAlias << sellerAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;
	scriptPubKeyOrig= GetScriptForDestination(sellerKey.GetID());
	scriptPubKeyBuyerOrig= GetScriptForDestination(buyerKey.GetID());


	const vector<unsigned char> &data = theOffer.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());

	vector<CRecipient> vecSend;
	CRecipient recipientAlias, recipient, recipientBuyer;


	scriptPubKeyBuyer << CScript::EncodeOP_N(OP_OFFER_ACCEPT) << theOffer.vchOffer << theOfferAccept.vchAcceptRand << vchFromString("0") << vchHashOffer << OP_2DROP <<  OP_2DROP << OP_DROP;
	scriptPubKeyBuyer += scriptPubKeyBuyerOrig;
	CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
	CreateRecipient(scriptPubKeyAlias, recipientAlias);

	vecSend.push_back(recipientBuyer);
	vecSend.push_back(recipientAlias);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, sellerAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneySyscoin(vecSend, recipientBuyer.nAmount+recipientAlias.nAmount+fee.nAmount, false, wtx, wtxAliasIn, sellerAlias.multiSigInfo.vchAliases.size() > 0);
	UniValue res(UniValue::VARR);
	if(sellerAlias.multiSigInfo.vchAliases.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("syscoinsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
		}
		else
		{
			res.push_back(hex_str);
			res.push_back("false");
		}
	}
	else
		res.push_back(wtx.GetHash().GetHex());
	return res;
}
UniValue offerinfo(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("offerinfo <guid>\n"
				"Show offer details\n");

	UniValue oOffer(UniValue::VOBJ);
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	string offer = stringFromVch(vchOffer);
	COffer theOffer;
	vector<COffer> vtxPos, vtxLinkPos;
    // get transaction pointed to by offer
	CTransaction tx;
	if(!GetTxAndVtxOfOffer( vchOffer, theOffer, tx, vtxPos, true))
		throw runtime_error("failed to read offer transaction from disk");

	// check that the seller isn't banned level 2
	CTransaction aliastx;
	CAliasIndex alias;
	if(!GetTxOfAlias(theOffer.vchAlias, alias, aliastx, true))
		throw runtime_error("Could not find the alias associated with this offer");
	if(theOffer.safetyLevel >= SAFETY_LEVEL2)
		throw runtime_error("offer has been banned");
	if(alias.safetyLevel >= SAFETY_LEVEL2)
		throw runtime_error("offer owner has been banned");

	CTransaction linkTx;
	COffer linkOffer;
	vector<COffer> myLinkedVtxPos;
	CTransaction linkaliastx;
	CAliasIndex linkAlias;
	if( !theOffer.vchLinkOffer.empty())
	{
		if(!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, linkTx, myLinkedVtxPos, true))
			throw runtime_error("failed to read linked offer transaction from disk");

		if(!GetTxOfAlias(linkOffer.vchAlias, linkAlias, linkaliastx, true))
			throw runtime_error("Could not find the alias associated with this linked offer");
		if(linkOffer.safetyLevel >= SAFETY_LEVEL2)
			throw runtime_error("root offer has been banned");
		if(linkAlias.safetyLevel >= SAFETY_LEVEL2)
			throw runtime_error("root offer owner has been banned");
	}

	uint64_t nHeight;
	int expired;
	int expires_in;
	int expired_block;

	expired = 0;
	expires_in = 0;
	expired_block = 0;
    nHeight = vtxPos.back().nHeight;
	vector<unsigned char> vchCert;
	if(!theOffer.vchCert.empty())
		vchCert = theOffer.vchCert;
	oOffer.push_back(Pair("offer", offer));
	oOffer.push_back(Pair("cert", stringFromVch(vchCert)));
	oOffer.push_back(Pair("txid", tx.GetHash().GetHex()));
	expired_block = nHeight + GetOfferExpirationDepth();
    if(expired_block < chainActive.Tip()->nHeight)
	{
		expired = 1;
	}
	expires_in = expired_block - chainActive.Tip()->nHeight;
	oOffer.push_back(Pair("expires_in", expires_in));
	oOffer.push_back(Pair("expired_block", expired_block));
	oOffer.push_back(Pair("expired", expired));
	oOffer.push_back(Pair("height", strprintf("%llu", nHeight)));
	oOffer.push_back(Pair("category", stringFromVch(theOffer.sCategory)));
	oOffer.push_back(Pair("title", stringFromVch(theOffer.sTitle)));
	int nQty = theOffer.nQty;
	if(!theOffer.vchLinkOffer.empty())
		nQty = linkOffer.nQty;
	if(nQty == -1)
		oOffer.push_back(Pair("quantity", "unlimited"));
	else
		oOffer.push_back(Pair("quantity", strprintf("%d", nQty)));
	oOffer.push_back(Pair("currency", stringFromVch(theOffer.sCurrencyCode)));


	int precision = 2;
	CAmount nPricePerUnit = convertSyscoinToCurrencyCode(alias.vchAliasPeg, theOffer.sCurrencyCode, theOffer.GetPrice(), nHeight, precision);
	oOffer.push_back(Pair("sysprice", theOffer.GetPrice()));
	oOffer.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real())));

	oOffer.push_back(Pair("ismine", IsSyscoinTxMine(aliastx, "alias")  ? "true" : "false"));
	if(!theOffer.vchLinkOffer.empty()) {
		oOffer.push_back(Pair("commission", strprintf("%d", theOffer.nCommission)));
		oOffer.push_back(Pair("offerlink", "true"));
		oOffer.push_back(Pair("offerlink_guid", stringFromVch(theOffer.vchLinkOffer)));
		oOffer.push_back(Pair("offerlink_seller", stringFromVch(linkOffer.vchAlias)));

	}
	else
	{
		oOffer.push_back(Pair("commission", "0"));
		oOffer.push_back(Pair("offerlink", "false"));
		oOffer.push_back(Pair("offerlink_guid", ""));
		oOffer.push_back(Pair("offerlink_seller", ""));
	}
	oOffer.push_back(Pair("exclusive_resell", theOffer.linkWhitelist.bExclusiveResell ? "ON" : "OFF"));
	oOffer.push_back(Pair("private", theOffer.bPrivate ? "Yes" : "No"));
	oOffer.push_back(Pair("safesearch", theOffer.safeSearch? "Yes" : "No"));
	unsigned char safetyLevel = max(theOffer.safetyLevel, alias.safetyLevel );
	safetyLevel = max(safetyLevel, linkOffer.safetyLevel );
	safetyLevel = max(safetyLevel, linkAlias.safetyLevel );
	oOffer.push_back(Pair("safetylevel", safetyLevel));
	int paymentOptions = theOffer.paymentOptions;
	if(!theOffer.vchLinkOffer.empty())
		paymentOptions = linkOffer.paymentOptions;
	oOffer.push_back(Pair("paymentoptions", paymentOptions));
	oOffer.push_back(Pair("paymentoptions_display", GetPaymentOptionsString(paymentOptions)));
	oOffer.push_back(Pair("alias_peg", stringFromVch(alias.vchAliasPeg)));
	oOffer.push_back(Pair("description", stringFromVch(theOffer.sDescription)));
	oOffer.push_back(Pair("alias", stringFromVch(theOffer.vchAlias)));
	CSyscoinAddress address;
	alias.GetAddress(&address);
	if(!address.IsValid())
		throw runtime_error("Invalid alias address");
	oOffer.push_back(Pair("address", address.ToString()));

	float rating = 0;
	if(alias.nRatingCountAsSeller > 0)
		rating = roundf(alias.nRatingAsSeller/(float)alias.nRatingCountAsSeller);
	oOffer.push_back(Pair("alias_rating",(int)rating));
	oOffer.push_back(Pair("alias_rating_count",(int)alias.nRatingCountAsSeller));
	oOffer.push_back(Pair("geolocation", stringFromVch(theOffer.vchGeoLocation)));
	int sold = theOffer.nSold;
	if(!theOffer.vchLinkOffer.empty())
		sold = linkOffer.nSold;
	oOffer.push_back(Pair("offers_sold", sold));

	return oOffer;

}
UniValue offeracceptlist(const UniValue& params, bool fHelp) {
    if (fHelp || 2 < params.size() || params.size() < 1)
        throw runtime_error("offeracceptlist [\"alias\",...] [acceptguid='']\n"
                "list offer purchases that an array of aliases own");
	UniValue aliases = params[0].get_array();
	vector<unsigned char> vchNameUniq;
	if (params.size() >= 2)
		vchNameUniq = vchFromValue(params[1]);
	UniValue aoOfferAccepts(UniValue::VARR);
	map< vector<unsigned char>, int > vNamesI;
	map< vector<unsigned char>, int > vNamesA;
	for(int i =0;i<aliases.size();i++)
	{
		string name = aliases[i].get_str();
		vector<unsigned char> vchAlias = vchFromString(name);
		vector<CAliasIndex> vtxPos;
		if (!paliasdb->ReadAlias(vchAlias, vtxPos) || vtxPos.empty())
			continue;
		const CAliasIndex &alias = vtxPos.back();
		CTransaction aliastx;
		uint256 txHash;
		if (!GetSyscoinTransaction(alias.nHeight, alias.txHash, aliastx, Params().GetConsensus()))
			continue;
		
		CTransaction tx, offerTx, acceptTx, aliasTx, linkTx, linkAliasTx, offerTxTmp;
		COffer theOffer, offerTmp, linkOffer;
		CAliasIndex linkAlias;
		vector<COffer> vtxOfferPos, vtxAcceptPos, vtxLinkPos, vtxAliasLinkPos;
		vector<unsigned char> vchOffer;
		uint256 blockHash;
		uint256 hash;

		
		for(std::vector<CAliasIndex>::reverse_iterator it = vtxPos.rbegin(); it != vtxPos.rend(); ++it) {
			const CAliasIndex& theAlias = *it;
			if(!GetSyscoinTransaction(theAlias.nHeight, theAlias.txHash, tx, Params().GetConsensus()))
				continue;
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			if (!DecodeOfferTx(tx, op, nOut, vvch))
				continue;
			if(!GetTxAndVtxOfOffer( vvch[0], offerTmp, offerTx, vtxOfferPos, true))
				continue;

			// get unique offers
			if (vNamesI.find(vvch[0]) != vNamesI.end())
				continue;

			vNamesI[vvch[0]] = offerTmp.nHeight;
			// this is needed because offer accepts dont use seller alias as input (they use buyers obviously) and we dont them in our alias history but they exist in our offer history
			for(int i=vtxOfferPos.size()-1;i>=0;i--) {

				const COffer &theOffer = vtxOfferPos[i];
				if(theOffer.accept.IsNull())
					continue;
				// get unique accepts
				if (vNamesA.find(theOffer.accept.vchAcceptRand) != vNamesA.end())
					continue;
				if (vchNameUniq.size() > 0 && vchNameUniq != theOffer.accept.vchAcceptRand)
					continue;

				// skip any feedback transactions
				if(!GetSyscoinTransaction(theOffer.nHeight, theOffer.txHash, offerTxTmp, Params().GetConsensus()))
					continue;

				if (!DecodeOfferTx(offerTxTmp, op, nOut, vvch)
        			|| (op != OP_OFFER_ACCEPT))
					continue;

				
				int nHeight = theOffer.accept.nAcceptHeight;
				vNamesA[theOffer.accept.vchAcceptRand] = nHeight;

				bool commissionPaid = false;
				bool discountApplied = false;
				// need to show 3 different possible prices:
				// LINKED OFFERS:
				// for buyer (full price) #1
				// for affiliate (commission + discount) #2
				// for merchant (discounted) #3
				// NON-LINKED OFFERS;
				// for merchant (discounted) #3
				// for buyer (full price) #1


				CAmount priceAtTimeOfAccept = theOffer.GetPrice();
				if(theOffer.vchLinkOffer.empty())
				{
					// NON-LINKED merchant
					if(vchAlias == theOffer.vchAlias)
					{
						priceAtTimeOfAccept = theOffer.accept.nPrice;
						if(theOffer.GetPrice() != priceAtTimeOfAccept)
							discountApplied = true;
					}
					// NON-LINKED buyer
					else if(vchAlias == theOffer.accept.vchBuyerAlias)
					{
						priceAtTimeOfAccept = theOffer.GetPrice();
						commissionPaid = false;
						discountApplied = false;
					}
				}
				// linked offer
				else
				{
					GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, linkTx, vtxLinkPos, true);
					linkOffer.nHeight = nHeight;
					linkOffer.GetOfferFromList(vtxLinkPos);
					// You are the merchant
					if(vchAlias == linkOffer.vchAlias)
					{
						commissionPaid = false;
						priceAtTimeOfAccept = theOffer.accept.nPrice;
						if(linkOffer.GetPrice() != priceAtTimeOfAccept)
							discountApplied = true;
					}
					// You are the affiliate
					else if(vchAlias == theOffer.vchAlias)
					{
						// full price with commission - discounted merchant price = commission + discount
						priceAtTimeOfAccept = theOffer.GetPrice() -  theOffer.accept.nPrice;
						commissionPaid = true;
						discountApplied = false;
					}
				}
				UniValue oOfferAccept(UniValue::VOBJ);
				string sHeight = strprintf("%llu", theOffer.nHeight);
				oOfferAccept.push_back(Pair("offer", stringFromVch(theOffer.vchOffer)));
				string sTime;
				CBlockIndex *pindex = chainActive[theOffer.nHeight];
				if (pindex) {
					sTime = strprintf("%llu", pindex->nTime);
				}
				int avgBuyerRating, avgSellerRating;
				vector<CFeedback> buyerFeedBacks, sellerFeedBacks;

				GetFeedback(buyerFeedBacks, avgBuyerRating, FEEDBACKBUYER, theOffer.accept.feedback);
				GetFeedback(sellerFeedBacks, avgSellerRating, FEEDBACKSELLER, theOffer.accept.feedback);


				oOfferAccept.push_back(Pair("id", stringFromVch(theOffer.accept.vchAcceptRand)));
				oOfferAccept.push_back(Pair("txid", theOffer.txHash.GetHex()));
				oOfferAccept.push_back(Pair("title", stringFromVch(theOffer.sTitle)));
				string strExtId = "";
				if(!theOffer.accept.txExtId.IsNull())
					strExtId = theOffer.accept.txExtId.GetHex();
				oOfferAccept.push_back(Pair("exttxid", strExtId));
				oOfferAccept.push_back(Pair("paymentoption", (int)theOffer.accept.nPaymentOption));
				oOfferAccept.push_back(Pair("paymentoption_display", GetPaymentOptionsString(theOffer.accept.nPaymentOption)));
				oOfferAccept.push_back(Pair("height", sHeight));
				oOfferAccept.push_back(Pair("time", sTime));
				oOfferAccept.push_back(Pair("quantity", strprintf("%d", theOffer.accept.nQty)));
				oOfferAccept.push_back(Pair("currency", stringFromVch(theOffer.sCurrencyCode)));
				if(theOffer.GetPrice() > 0)
					oOfferAccept.push_back(Pair("offer_discount_percentage", strprintf("%.2f%%", 100.0f - 100.0f*((float)theOffer.accept.nPrice/(float)theOffer.nPrice))));
				else
					oOfferAccept.push_back(Pair("offer_discount_percentage", "0%"));

				int precision = 2;
				CAmount nPricePerUnit = convertSyscoinToCurrencyCode(theAlias.vchAliasPeg, theOffer.sCurrencyCode, priceAtTimeOfAccept, theOffer.accept.nAcceptHeight, precision);
				CAmount sysTotal = priceAtTimeOfAccept * theOffer.accept.nQty;
				oOfferAccept.push_back(Pair("systotal", sysTotal));
				oOfferAccept.push_back(Pair("sysprice", priceAtTimeOfAccept));
				oOfferAccept.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real())));
				oOfferAccept.push_back(Pair("total", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() * theOffer.accept.nQty )));
				oOfferAccept.push_back(Pair("buyer", stringFromVch(theOffer.accept.vchBuyerAlias)));
				oOfferAccept.push_back(Pair("seller", stringFromVch(theOffer.vchAlias)));
				oOfferAccept.push_back(Pair("ismine", IsSyscoinTxMine(aliastx, "alias")? "true" : "false"));
				string statusStr = "Paid";
				if(!theOffer.accept.txExtId.IsNull())
					statusStr = "Paid with external coin";
				else if(commissionPaid)
					statusStr = "Paid commission";
				else if(discountApplied)
					statusStr = "Paid with discount applied";
				if(theOffer.accept.bPaymentAck)
					statusStr += " (acknowledged)";
				oOfferAccept.push_back(Pair("status",statusStr));
				UniValue oBuyerFeedBack(UniValue::VARR);
				for(unsigned int j =0;j<buyerFeedBacks.size();j++)
				{
					UniValue oFeedback(UniValue::VOBJ);
					string sFeedbackTime;
					CBlockIndex *pindex = chainActive[buyerFeedBacks[j].nHeight];
					if (pindex) {
						sFeedbackTime = strprintf("%llu", pindex->nTime);
					}

					oFeedback.push_back(Pair("txid", buyerFeedBacks[j].txHash.GetHex()));
					oFeedback.push_back(Pair("time", sFeedbackTime));
					oFeedback.push_back(Pair("rating", buyerFeedBacks[j].nRating));
					oFeedback.push_back(Pair("feedbackuser", buyerFeedBacks[j].nFeedbackUserFrom));
					oFeedback.push_back(Pair("feedback", stringFromVch(buyerFeedBacks[j].vchFeedback)));
					oBuyerFeedBack.push_back(oFeedback);
				}
				oOfferAccept.push_back(Pair("buyer_feedback", oBuyerFeedBack));
				UniValue oSellerFeedBack(UniValue::VARR);
				for(unsigned int j =0;j<sellerFeedBacks.size();j++)
				{
					UniValue oFeedback(UniValue::VOBJ);
					string sFeedbackTime;
					CBlockIndex *pindex = chainActive[sellerFeedBacks[j].nHeight];
					if (pindex) {
						sFeedbackTime = strprintf("%llu", pindex->nTime);
					}
					oFeedback.push_back(Pair("txid", sellerFeedBacks[j].txHash.GetHex()));
					oFeedback.push_back(Pair("time", sFeedbackTime));
					oFeedback.push_back(Pair("rating", sellerFeedBacks[j].nRating));
					oFeedback.push_back(Pair("feedbackuser", sellerFeedBacks[j].nFeedbackUserFrom));
					oFeedback.push_back(Pair("feedback", stringFromVch(sellerFeedBacks[j].vchFeedback)));
					oSellerFeedBack.push_back(oFeedback);
				}
				oOfferAccept.push_back(Pair("seller_feedback", oSellerFeedBack));
				unsigned int ratingCount = 0;
				if(avgSellerRating > 0)
					ratingCount++;
				if(avgBuyerRating > 0)
					ratingCount++;
				if(ratingCount == 0)
					ratingCount = 1;
				float totalAvgRating = roundf((avgSellerRating+avgBuyerRating)/(float)ratingCount);
				oOfferAccept.push_back(Pair("avg_rating", (int)totalAvgRating));
				string strMessage = string("");
				if(!DecryptMessage(alias.vchPubKey, theOffer.accept.vchMessage, strMessage))
					strMessage = _("Encrypted for owner of offer");
				oOfferAccept.push_back(Pair("pay_message", strMessage));
				aoOfferAccepts.push_back(oOfferAccept);

			}
		}
	}
    return aoOfferAccepts;
}
UniValue offerlist(const UniValue& params, bool fHelp) {
    if (fHelp || 2 < params.size() || params.size() < 1)
        throw runtime_error("offerlist <alias> [<offer>]\n"
                "list offers that an alias owns");

    vector<unsigned char> vchAlias = vchFromValue(params[0]);
	string name = stringFromVch(vchAlias);
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vchAlias, vtxPos) || vtxPos.empty())
		throw runtime_error("failed to read from alias DB");
	const CAliasIndex &alias = vtxPos.back();
	CTransaction aliastx;
	uint256 txHash;
	if (!GetSyscoinTransaction(alias.nHeight, alias.txHash, aliastx, Params().GetConsensus()))
	{
		throw runtime_error("failed to read alias transaction");
	}
    vector<unsigned char> vchNameUniq;
    if (params.size() == 2)
        vchNameUniq = vchFromValue(params[1]);

    UniValue oRes(UniValue::VARR);
    map< vector<unsigned char>, int > vNamesI;
    map< vector<unsigned char>, UniValue > vNamesO;
    CTransaction tx;
    uint64_t nHeight;
	for(std::vector<CAliasIndex>::reverse_iterator it = vtxPos.rbegin(); it != vtxPos.rend(); ++it) {
		const CAliasIndex& theAlias = *it;
		if(!GetSyscoinTransaction(theAlias.nHeight, theAlias.txHash, tx, Params().GetConsensus()))
			continue;
		int expired = 0;
		int expires_in = 0;
		int expired_block = 0;

            // decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeOfferTx(tx, op, nOut, vvch)
            	|| (op == OP_OFFER_ACCEPT))
                continue;

            // get the txn name
            const vector<unsigned char> &vchOffer = vvch[0];
			if (vNamesI.find(vchOffer) != vNamesI.end())
				continue;
			// skip this offer if it doesn't match the given filter value
			if (vchNameUniq.size() > 0 && vchNameUniq != vchOffer)
				continue;

			vector<COffer> vtxOfferPos;
			if (!pofferdb->ReadOffer(vchOffer, vtxOfferPos) || vtxOfferPos.empty())
				continue;

			const COffer &theOffer = vtxOfferPos.back();
			COffer linkOffer;
			CAliasIndex linkAlias;
			vector<COffer> myLinkedOfferVtxPos;
			vector<CAliasIndex> myLinkedAliasVtxPos;
			if( !theOffer.vchLinkOffer.empty())
			{
				if (!pofferdb->ReadOffer(theOffer.vchLinkOffer, myLinkedOfferVtxPos) || myLinkedOfferVtxPos.empty())
					continue;

				linkOffer = myLinkedOfferVtxPos.back();
				if (!paliasdb->ReadAlias(linkOffer.vchAlias, myLinkedAliasVtxPos) || myLinkedAliasVtxPos.empty())
					continue;
				linkAlias = myLinkedAliasVtxPos.back();
			}

			nHeight = theOffer.nHeight;
            // build the output UniValue
            UniValue oName(UniValue::VOBJ);
            oName.push_back(Pair("offer", stringFromVch(vchOffer)));
			vector<unsigned char> vchCert;
			if(!theOffer.vchCert.empty())
				vchCert = theOffer.vchCert;
			oName.push_back(Pair("cert", stringFromVch(vchCert)));
            oName.push_back(Pair("title", stringFromVch(theOffer.sTitle)));
            oName.push_back(Pair("category", stringFromVch(theOffer.sCategory)));
            oName.push_back(Pair("description", stringFromVch(theOffer.sDescription)));
			int precision = 2;
			CAmount nPricePerUnit = convertSyscoinToCurrencyCode(theAlias.vchAliasPeg, theOffer.sCurrencyCode, theOffer.GetPrice(), theOffer.nHeight, precision);
			oName.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() )));

			oName.push_back(Pair("currency", stringFromVch(theOffer.sCurrencyCode) ) );
			oName.push_back(Pair("commission", strprintf("%d", theOffer.nCommission)));
			int nQty = theOffer.nQty;
			if(!theOffer.vchLinkOffer.empty())
				nQty = linkOffer.nQty;
			if(nQty == -1)
				oName.push_back(Pair("quantity", "unlimited"));
			else
				oName.push_back(Pair("quantity", strprintf("%d", nQty)));
			int paymentOptions = theOffer.paymentOptions;
			if(!theOffer.vchLinkOffer.empty())
				paymentOptions = linkOffer.paymentOptions;
			oName.push_back(Pair("paymentoptions", paymentOptions));
			oName.push_back(Pair("paymentoptions_display", GetPaymentOptionsString(paymentOptions)));
			oName.push_back(Pair("exclusive_resell", theOffer.linkWhitelist.bExclusiveResell ? "ON" : "OFF"));


			oName.push_back(Pair("alias_peg", stringFromVch(theAlias.vchAliasPeg)));
			oName.push_back(Pair("private", theOffer.bPrivate ? "Yes" : "No"));
			oName.push_back(Pair("safesearch", theOffer.safeSearch? "Yes" : "No"));
			unsigned char safetyLevel = max(theOffer.safetyLevel, alias.safetyLevel );
			safetyLevel = max(safetyLevel, linkOffer.safetyLevel );
			safetyLevel = max(safetyLevel, linkAlias.safetyLevel );
			oName.push_back(Pair("safetylevel", safetyLevel));
			oName.push_back(Pair("geolocation", stringFromVch(theOffer.vchGeoLocation)));
			int sold = theOffer.nSold;
			if(!theOffer.vchLinkOffer.empty())
				sold = linkOffer.nSold;
			oName.push_back(Pair("offers_sold", sold));
			expired_block = nHeight + GetOfferExpirationDepth();
            if(expired_block < chainActive.Tip()->nHeight)
			{
				expired = 1;
			}
			expires_in = expired_block - chainActive.Tip()->nHeight;

			oName.push_back(Pair("alias", stringFromVch(theOffer.vchAlias)));
			float rating = 0;
			if(alias.nRatingCountAsSeller > 0)
				rating = roundf(alias.nRatingAsSeller/(float)alias.nRatingCountAsSeller);
			oName.push_back(Pair("alias_rating",(int)rating));
			oName.push_back(Pair("alias_rating_count",(int)alias.nRatingCountAsSeller));
			oName.push_back(Pair("expires_in", expires_in));
			oName.push_back(Pair("expires_on", expired_block));
			oName.push_back(Pair("expired", expired));
			oName.push_back(Pair("ismine", IsSyscoinTxMine(aliastx, "alias") ? "true" : "false"));

            vNamesI[vchOffer] = nHeight;
            vNamesO[vchOffer] = oName;
	}


    BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vNamesO)
        oRes.push_back(item.second);

    return oRes;
}
UniValue offerhistory(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("offerhistory <offer>\n"
				"List all stored values of an offer.\n");

	UniValue oRes(UniValue::VARR);
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	string offer = stringFromVch(vchOffer);

	{

		vector<COffer> vtxPos;
		if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
			throw runtime_error("failed to read from offer DB");
		COffer txPos2;
		uint256 txHash;
		BOOST_FOREACH(txPos2, vtxPos) {
			COffer linkOffer;
			if( !txPos2.vchLinkOffer.empty())
			{
				vector<COffer> vtxLinkPos;
				CTransaction linkTx;
				if(!GetTxAndVtxOfOffer( txPos2.vchLinkOffer, linkOffer, linkTx, vtxLinkPos, true))
					continue;
				linkOffer.nHeight = txPos2.nHeight;
				linkOffer.GetOfferFromList(vtxLinkPos);
			}
			vector<CAliasIndex> vtxAliasPos;
			if(!paliasdb->ReadAlias(txPos2.vchAlias, vtxAliasPos) || vtxAliasPos.empty())
				continue;
			CAliasIndex theAlias;
			theAlias.nHeight = txPos2.nHeight;
			theAlias.GetAliasFromList(vtxAliasPos);
			txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetSyscoinTransaction(txPos2.nHeight, txHash, tx, Params().GetConsensus())) {
				error("could not read txpos");
				continue;
			}
            // decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeOfferTx(tx, op, nOut, vvch)
            	|| !IsOfferOp(op) )
                continue;

			int expired = 0;
			int expires_in = 0;
			int expired_block = 0;
			UniValue oOffer(UniValue::VOBJ);
			vector<unsigned char> vchValue;
			uint64_t nHeight;
			nHeight = txPos2.nHeight;
			COffer theOfferA = txPos2;
			oOffer.push_back(Pair("offer", offer));
			string opName = offerFromOp(op);
			COffer offer(tx);
			if(offer.accept.bPaymentAck)
				opName += "("+_("acknowledged")+")";
			else if(!offer.accept.feedback.empty())
				opName += "("+_("feedback")+")";

			
			oOffer.push_back(Pair("offertype", opName));
			vector<unsigned char> vchCert;
			if(!theOfferA.vchCert.empty())
				vchCert = theOfferA.vchCert;
			oOffer.push_back(Pair("cert", stringFromVch(vchCert)));
            oOffer.push_back(Pair("title", stringFromVch(theOfferA.sTitle)));
            oOffer.push_back(Pair("category", stringFromVch(theOfferA.sCategory)));
            oOffer.push_back(Pair("description", stringFromVch(theOfferA.sDescription)));
			int precision = 2;
			CAmount nPricePerUnit = convertSyscoinToCurrencyCode(theAlias.vchAliasPeg, theOfferA.sCurrencyCode, theOfferA.GetPrice(), theOfferA.nHeight, precision);
			oOffer.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() )));

			oOffer.push_back(Pair("currency", stringFromVch(theOfferA.sCurrencyCode) ) );
			oOffer.push_back(Pair("commission", strprintf("%d", theOfferA.nCommission)));
			int nQty = theOfferA.nQty;
			if(!theOfferA.vchLinkOffer.empty())
				nQty = linkOffer.nQty;
			if(nQty == -1)
				oOffer.push_back(Pair("quantity", "unlimited"));
			else
				oOffer.push_back(Pair("quantity", strprintf("%d", nQty)));

			oOffer.push_back(Pair("txid", tx.GetHash().GetHex()));
			expired_block = nHeight + GetOfferExpirationDepth();
            if(expired_block < chainActive.Tip()->nHeight)
			{
				expired = 1;
			}
			expires_in = expired_block - chainActive.Tip()->nHeight;

			oOffer.push_back(Pair("alias", stringFromVch(theOfferA.vchAlias)));
			float rating = 0;
			if(!vtxAliasPos.empty() && vtxAliasPos.back().nRatingCountAsSeller > 0)
				rating = roundf(vtxAliasPos.back().nRatingAsSeller/(float)vtxAliasPos.back().nRatingCountAsSeller);
			oOffer.push_back(Pair("alias_rating",(int)rating));
			oOffer.push_back(Pair("alias_rating_count",(int)vtxAliasPos.back().nRatingCountAsSeller));
			oOffer.push_back(Pair("expires_in", expires_in));
			oOffer.push_back(Pair("expires_on", expired_block));
			oOffer.push_back(Pair("expired", expired));
			oOffer.push_back(Pair("height", strprintf("%d", theOfferA.nHeight)));
			oRes.push_back(oOffer);
		}
	}
	return oRes;
}
UniValue offerfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 4)
		throw runtime_error(
				"offerfilter [[[[[regexp]] from=0]] safesearch='Yes' category]\n"
						"scan and filter offers\n"
						"[regexp] : apply [regexp] on offers, empty means all offers\n"
						"[from] : show results from this GUID [from], 0 means first.\n"
						"[safesearch] : shows all offers that are safe to display (not on the ban list)\n"
						"[category] : category you want to search in, empty for all\n"
						"offerfilter \"\" 5 # list offers updated in last 5 blocks\n"
						"offerfilter \"^offer\" # list all offers starting with \"offer\"\n"
						"offerfilter 36000 0 0 stat # display stats (number of offers) on active offers\n");

	string strRegexp;
	vector<unsigned char> vchOffer;
	string strCategory;
	bool safeSearch = true;

	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		vchOffer = vchFromValue(params[1]);

	if (params.size() > 2)
		safeSearch = params[2].get_str()=="On"? true: false;

	if (params.size() > 3)
		strCategory = params[3].get_str();

	UniValue oRes(UniValue::VARR);


	vector<pair<vector<unsigned char>, COffer> > offerScan;
	if (!pofferdb->ScanOffers(vchOffer, strRegexp, safeSearch, strCategory, 25, offerScan))
		throw runtime_error("scan failed");

	pair<vector<unsigned char>, COffer> pairScan;
	BOOST_FOREACH(pairScan, offerScan) {
		COffer txOffer = pairScan.second;
		const string &offer = stringFromVch(pairScan.first);
		vector<COffer> vtxPos, myLinkVtxPos;
		vector<CAliasIndex> vtxAliasPos;
		if (!pofferdb->ReadOffer(vchFromString(offer), vtxPos) || vtxPos.empty())
			continue;

		if(!paliasdb->ReadAlias(txOffer.vchAlias, vtxAliasPos) || vtxAliasPos.empty())
			continue;
		COffer linkOffer;
		if (pofferdb->ExistsOffer(txOffer.vchLinkOffer)) {
			if (pofferdb->ReadOffer(txOffer.vchLinkOffer, myLinkVtxPos) && !myLinkVtxPos.empty())
			{
				linkOffer = myLinkVtxPos.back();
			}
		}
		int expires_in = 0;
		int expired_block = 0;
		int nHeight = txOffer.nHeight;
		UniValue oOffer(UniValue::VOBJ);
		oOffer.push_back(Pair("offer", offer));
		vector<unsigned char> vchCert;
		if(!txOffer.vchCert.empty())
			vchCert = txOffer.vchCert;
		oOffer.push_back(Pair("cert", stringFromVch(vchCert)));
        oOffer.push_back(Pair("title", stringFromVch(txOffer.sTitle)));
		oOffer.push_back(Pair("description", stringFromVch(txOffer.sDescription)));
        oOffer.push_back(Pair("category", stringFromVch(txOffer.sCategory)));
		int precision = 2;
		CAmount nPricePerUnit = convertSyscoinToCurrencyCode(vtxAliasPos.back().vchAliasPeg, txOffer.sCurrencyCode, txOffer.GetPrice(), nHeight, precision);
		oOffer.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() )));
		oOffer.push_back(Pair("currency", stringFromVch(txOffer.sCurrencyCode)));
		oOffer.push_back(Pair("commission", strprintf("%d", txOffer.nCommission)));
		int nQty = txOffer.nQty;
		if(!txOffer.vchLinkOffer.empty())
			nQty = linkOffer.nQty;
		if(nQty == -1)
			oOffer.push_back(Pair("quantity", "unlimited"));
		else
			oOffer.push_back(Pair("quantity", strprintf("%d", nQty)));
		int paymentOptions = txOffer.paymentOptions;
		if(!txOffer.vchLinkOffer.empty())
			paymentOptions = linkOffer.paymentOptions;
		oOffer.push_back(Pair("paymentoptions", paymentOptions));
		oOffer.push_back(Pair("paymentoptions_display", GetPaymentOptionsString(paymentOptions)));
		oOffer.push_back(Pair("exclusive_resell", txOffer.linkWhitelist.bExclusiveResell ? "ON" : "OFF"));
		oOffer.push_back(Pair("alias_peg", stringFromVch(vtxAliasPos.back().vchAliasPeg)));
		int sold = txOffer.nSold;
		if(!txOffer.vchLinkOffer.empty())
			sold = linkOffer.nSold;
		oOffer.push_back(Pair("offers_sold", sold));
		expired_block = nHeight + GetOfferExpirationDepth();
		expires_in = expired_block - chainActive.Tip()->nHeight;
		oOffer.push_back(Pair("private", txOffer.bPrivate ? "Yes" : "No"));
		oOffer.push_back(Pair("alias", stringFromVch(txOffer.vchAlias)));
		float rating = 0;
		if(!vtxAliasPos.empty() && vtxAliasPos.back().nRatingCountAsSeller > 0)
			rating = roundf(vtxAliasPos.back().nRatingAsSeller/(float)vtxAliasPos.back().nRatingCountAsSeller);
		oOffer.push_back(Pair("alias_rating",(int)rating));
		oOffer.push_back(Pair("alias_rating_count",(int)vtxAliasPos.back().nRatingCountAsSeller));
		oOffer.push_back(Pair("geolocation", stringFromVch(txOffer.vchGeoLocation)));
		oOffer.push_back(Pair("expires_in", expires_in));
		oOffer.push_back(Pair("expires_on", expired_block));
		oRes.push_back(oOffer);
	}


	return oRes;
}
bool GetAcceptByHash(std::vector<COffer> &offerList, COfferAccept &ca, COffer &offer) {
	if(offerList.empty())
		return false;
	for(std::vector<COffer>::reverse_iterator it = offerList.rbegin(); it != offerList.rend(); ++it) {
		const COffer& myoffer = *it;
		// skip null states
		if(myoffer.accept.IsNull())
			continue;
        if(myoffer.accept.vchAcceptRand == ca.vchAcceptRand) {
            ca = myoffer.accept;
			offer = myoffer;
			return true;
        }
    }
	return false;
}
std::string GetPaymentOptionsString(const uint32_t paymentOptions)
{
	vector<std::string> currencies;
	if(IsPaymentOptionInMask(paymentOptions, PAYMENTOPTION_SYS)) {
		currencies.push_back(std::string("SYS"));
	}
	if(IsPaymentOptionInMask(paymentOptions, PAYMENTOPTION_BTC)) {
		currencies.push_back(std::string("BTC"));
	}
	if(IsPaymentOptionInMask(paymentOptions, PAYMENTOPTION_ZEC)) {
		currencies.push_back(std::string("ZEC"));
	}
	return boost::algorithm::join(currencies, "+");
}
CChainParams::AddressType PaymentOptionToAddressType(const uint32_t paymentOption)
{
	CChainParams::AddressType myAddressType = CChainParams::ADDRESS_SYS;
	if(paymentOption == PAYMENTOPTION_ZEC)
		myAddressType = CChainParams::ADDRESS_ZEC;
	return myAddressType;
}

void OfferTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry)
{
	string opName = offerFromOp(op);
	COffer offer;
	if(!offer.UnserializeFromData(vchData, vchHash))
		return;


	bool isExpired = false;
	vector<CAliasIndex> aliasVtxPos;
	vector<COffer> offerVtxPos;
	CTransaction offertx, aliastx;
	COffer dbOffer;
	if(GetTxAndVtxOfOffer(offer.vchOffer, dbOffer, offertx, offerVtxPos, true))
	{
		dbOffer.nHeight = offer.nHeight;
		dbOffer.GetOfferFromList(offerVtxPos);
	}
	CAliasIndex dbAlias;
	if(GetTxAndVtxOfAlias(offer.vchAlias, dbAlias, aliastx, aliasVtxPos, isExpired, true))
	{
		dbAlias.nHeight = offer.nHeight;
		dbAlias.GetAliasFromList(aliasVtxPos);
	}
	string noDifferentStr = _("<No Difference Detected>");
	COffer offerop(offertx);
	if(offerop.accept.bPaymentAck)
		opName += "("+_("acknowledged")+")";
	else if(!offerop.accept.feedback.empty())
		opName += "("+_("feedback")+")";
	entry.push_back(Pair("txtype", opName));
	entry.push_back(Pair("offer", stringFromVch(offer.vchOffer)));

	if(!offer.linkWhitelist.IsNull())
	{
		string whitelistValue = noDifferentStr;
		if(offer.linkWhitelist.entries[0].nDiscountPct == 127)
			whitelistValue = _("Whitelist was cleared");
		else
			whitelistValue = _("Whitelist entries were added or removed");

		entry.push_back(Pair("whitelist", whitelistValue));
		return;
	}

	string titleValue = noDifferentStr;
	if(!offer.sTitle.empty() && offer.sTitle != dbOffer.sTitle)
		titleValue = stringFromVch(offer.sTitle);
	entry.push_back(Pair("title", titleValue));

	string certValue = noDifferentStr;
	if(!offer.vchCert.empty() && offer.vchCert != dbOffer.vchCert)
		certValue = stringFromVch(offer.vchCert);
	entry.push_back(Pair("cert", certValue));

	string aliasValue = noDifferentStr;
	if(!offer.vchAlias.empty() && offer.vchAlias != dbOffer.vchAlias)
		aliasValue = stringFromVch(offer.vchAlias);

	entry.push_back(Pair("alias", aliasValue));

	string linkOfferValue = noDifferentStr;
	if(!offer.vchLinkOffer.empty() && offer.vchLinkOffer != dbOffer.vchLinkOffer)
		linkOfferValue = stringFromVch(offer.vchLinkOffer);

	entry.push_back(Pair("offerlink", linkOfferValue));

	string commissionValue = noDifferentStr;
	if(offer.nCommission  != 0 && offer.nCommission != dbOffer.nCommission)
		commissionValue =  boost::lexical_cast<string>(offer.nCommission);
	entry.push_back(Pair("commission", commissionValue));

	string exclusiveResellValue = noDifferentStr;
	if(offer.linkWhitelist.bExclusiveResell != dbOffer.linkWhitelist.bExclusiveResell)
		exclusiveResellValue = offer.linkWhitelist.bExclusiveResell? "ON": "OFF";

	entry.push_back(Pair("exclusiveresell", exclusiveResellValue));

	string paymentOptionsValue = noDifferentStr;
	if(offer.paymentOptions > 0 && offer.paymentOptions != dbOffer.paymentOptions)
		paymentOptionsValue = GetPaymentOptionsString( offer.paymentOptions);

	entry.push_back(Pair("paymentoptions", paymentOptionsValue));

	string ackValue = noDifferentStr;
	if(offer.accept.bPaymentAck && offer.accept.bPaymentAck != dbOffer.accept.bPaymentAck)
		ackValue = offer.accept.bPaymentAck? "true": "false";

	entry.push_back(Pair("paymentacknowledge", ackValue));

	string categoryValue = noDifferentStr;
	if(!offer.sCategory.empty() && offer.sCategory != dbOffer.sCategory)
		categoryValue = stringFromVch(offer.sCategory);

	entry.push_back(Pair("category", categoryValue ));

	string geolocationValue = noDifferentStr;
	if(!offer.vchGeoLocation.empty() && offer.vchGeoLocation != dbOffer.vchGeoLocation)
		geolocationValue = stringFromVch(offer.vchGeoLocation);

	entry.push_back(Pair("geolocation", geolocationValue ));


	string descriptionValue = noDifferentStr;
	if(!offer.sDescription.empty() && offer.sDescription != dbOffer.sDescription)
		descriptionValue = stringFromVch(offer.sDescription);
	entry.push_back(Pair("description", descriptionValue));


	string qtyValue = noDifferentStr;
	if(offer.nQty != dbOffer.nQty)
		qtyValue =  boost::lexical_cast<string>(offer.nQty);
	entry.push_back(Pair("quantity", qtyValue));

	string currencyValue = noDifferentStr;
	if(!offer.sCurrencyCode.empty()  && offer.sCurrencyCode != dbOffer.sCurrencyCode)
		currencyValue = stringFromVch(offer.sCurrencyCode);
	entry.push_back(Pair("currency", currencyValue));


	string priceValue = noDifferentStr;
	if(offer.GetPrice() != dbOffer.GetPrice())
		priceValue = boost::lexical_cast<string>(offer.GetPrice());
	entry.push_back(Pair("price", priceValue));


	string safeSearchValue = noDifferentStr;
	if(offer.safeSearch != dbOffer.safeSearch)
		safeSearchValue = offer.safeSearch? "Yes": "No";

	entry.push_back(Pair("safesearch", safeSearchValue));

	string safetyLevelValue = noDifferentStr;
	if(offer.safetyLevel != dbOffer.safetyLevel)
		safetyLevelValue = offer.safetyLevel;

	entry.push_back(Pair("safetylevel", safetyLevelValue));

	string privateValue = noDifferentStr;
	if(offer.bPrivate != dbOffer.bPrivate)
		privateValue = offer.bPrivate? "Yes": "No";

	entry.push_back(Pair("private", privateValue ));

}
