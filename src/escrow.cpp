#include "escrow.h"
#include "offer.h"
#include "alias.h"
#include "cert.h"
#include "init.h"
#include "main.h"
#include "core_io.h"
#include "util.h"
#include "base58.h"
#include "core_io.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "policy/policy.h"
#include "script/script.h"
#include "chainparams.h"
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/predicate.hpp>
extern CScript _createmultisig_redeemScript(const UniValue& params);
using namespace std;
extern CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);
extern void SendMoneySyscoin(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInAlias=NULL, bool syscoinMultiSigTx=false, const CCoinControl* coinControl=NULL);
void PutToEscrowList(std::vector<CEscrow> &escrowList, CEscrow& index) {
	int i = escrowList.size() - 1;
	BOOST_REVERSE_FOREACH(CEscrow &o, escrowList) {
        if(index.nHeight != 0 && o.nHeight ==index.nHeight) {
        	escrowList[i] = index;
            return;
        }
        else if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	escrowList[i] = index;
            return;
        }
        i--;
	}
    escrowList.push_back(index);
}
bool IsEscrowOp(int op) {
    return op == OP_ESCROW_ACTIVATE
        || op == OP_ESCROW_RELEASE
        || op == OP_ESCROW_REFUND
		|| op == OP_ESCROW_COMPLETE;
}
// % fee on escrow value for arbiter
int64_t GetEscrowArbiterFee(int64_t escrowValue, float fEscrowFee) {

	if(fEscrowFee == 0)
		fEscrowFee = 0.005;
	int fee = 1/fEscrowFee;
	int64_t nFee = escrowValue/fee;
	if(nFee < DEFAULT_MIN_RELAY_TX_FEE)
		nFee = DEFAULT_MIN_RELAY_TX_FEE;
	return nFee;
}
int GetEscrowExpirationDepth() {
	#ifdef ENABLE_DEBUGRPC
    return 1440;
  #else
    return 525600;
  #endif
}


string escrowFromOp(int op) {
    switch (op) {
    case OP_ESCROW_ACTIVATE:
        return "escrowactivate";
    case OP_ESCROW_RELEASE:
        return "escrowrelease";
    case OP_ESCROW_REFUND:
        return "escrowrefund";
	case OP_ESCROW_COMPLETE:
		return "escrowcomplete";
    default:
        return "<unknown escrow op>";
    }
}
bool CEscrow::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsEscrow(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsEscrow >> *this;

		const vector<unsigned char> &vchEscrowData = Serialize();
		uint256 calculatedHash = Hash(vchEscrowData.begin(), vchEscrowData.end());
		vector<unsigned char> vchRandEscrow= vchFromValue(calculatedHash.GetHex());
		if(vchRandEscrow != vchHash)
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
bool CEscrow::UnserializeFromTx(const CTransaction &tx) {
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
const vector<unsigned char> CEscrow::Serialize() {
    CDataStream dsEscrow(SER_NETWORK, PROTOCOL_VERSION);
    dsEscrow << *this;
    const vector<unsigned char> vchData(dsEscrow.begin(), dsEscrow.end());
    return vchData;

}
bool CEscrowDB::ScanEscrows(const std::vector<unsigned char>& vchEscrow, const string& strRegexp, unsigned int nMax,
        std::vector<std::pair<std::vector<unsigned char>, CEscrow> >& escrowScan) {
	string strSearchLower = strRegexp;
	boost::algorithm::to_lower(strSearchLower);
	int nMaxAge  = GetEscrowExpirationDepth();
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->Seek(make_pair(string("escrowi"), vchEscrow));
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
		pair<string, vector<unsigned char> > key;
        try {
			if (pcursor->GetKey(key) && key.first == "escrowi") {
            	vector<unsigned char> vchEscrow = key.second;
                vector<CEscrow> vtxPos;
				pcursor->GetValue(vtxPos);
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CEscrow &txPos = vtxPos.back();
  				if (chainActive.Tip()->nHeight - txPos.nHeight >= nMaxAge && txPos.op == OP_ESCROW_COMPLETE)
				{
					pcursor->Next();
					continue;
				}
				const string &escrow = stringFromVch(vchEscrow);
				const string &offerstr = stringFromVch(txPos.vchOffer);

				string buyerAliasLower = stringFromVch(txPos.vchBuyerAlias);
				string sellerAliasLower = stringFromVch(txPos.vchSellerAlias);
				string arbiterAliasLower = stringFromVch(txPos.vchArbiterAlias);

				if (strRegexp != "" && strRegexp != offerstr && strRegexp != escrow && strSearchLower != buyerAliasLower && strSearchLower != sellerAliasLower && strSearchLower != arbiterAliasLower)
				{
					pcursor->Next();
					continue;
				}
                escrowScan.push_back(make_pair(vchEscrow, txPos));
            }
            if (escrowScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}
int IndexOfEscrowOutput(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return -1;
    vector<vector<unsigned char> > vvch;
	int op;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeEscrowScript(out.scriptPubKey, op, vvch)) {
			return i;
		}
	}
	return -1;
}
bool GetTxOfEscrow(const vector<unsigned char> &vchEscrow,
        CEscrow& txPos, CTransaction& tx) {
    vector<CEscrow> vtxPos;
    if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
	// if escrow is refunded or claimed and its expired
	// if not refunded or claimed it cannot expire
    if ((nHeight + GetEscrowExpirationDepth()
            < chainActive.Tip()->nHeight) && txPos.op == OP_ESCROW_COMPLETE) {
        string escrow = stringFromVch(vchEscrow);
        LogPrintf("GetTxOfEscrow(%s) : expired", escrow.c_str());
        return false;
    }
    if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfEscrow() : could not read tx from disk");

    return true;
}
bool GetTxAndVtxOfEscrow(const vector<unsigned char> &vchEscrow,
        CEscrow& txPos, CTransaction& tx, vector<CEscrow> &vtxPos) {

    if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
	// if escrow is refunded or claimed and its expired
	// if not refunded or claimed it cannot expire
    if ((nHeight + GetEscrowExpirationDepth()
            < chainActive.Tip()->nHeight) && txPos.op == OP_ESCROW_COMPLETE) {
        string escrow = stringFromVch(vchEscrow);
        LogPrintf("GetTxOfEscrow(%s) : expired", escrow.c_str());
        return false;
    }
    if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfEscrow() : could not read tx from disk");

    return true;
}

bool DecodeAndParseEscrowTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CEscrow escrow;
	bool decode = DecodeEscrowTx(tx, op, nOut, vvch);
	bool parse = escrow.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeEscrowTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeEscrowScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
	if (!found) vvch.clear();
    return found;
}

bool DecodeEscrowScript(const CScript& script, int& op,
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
    return IsEscrowOp(op);
}
bool DecodeEscrowScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeEscrowScript(script, op, vvch, pc);
}

CScript RemoveEscrowScriptPrefix(const CScript& scriptIn) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeEscrowScript(scriptIn, op, vvch, pc))
	{
        throw runtime_error("RemoveEscrowScriptPrefix() : could not decode escrow script");
	}

    return CScript(pc, scriptIn.end());
}
bool ValidateExternalPayment(const CEscrow& theEscrow, const COffer& theOffer, const CAliasIndex &sellerAlias, const uint64_t nAcceptHeight, const COfferLinkWhitelistEntry &foundEntry, const bool &dontaddtodb, const CAmount &nCommission, const CSyscoinAddress& multisigaddress, string& errorMessage)
{
	CTransaction fundingTx;
	if (!DecodeHexTx(fundingTx,HexStr(theEscrow.rawTx)))
	{
		errorMessage = _("Could not find decode external transaction");
		return true;
	}

	const uint256 &txHash = fundingTx.GetHash();
	if(pescrowdb->ExistsEscrowTx(txHash) || pofferdb->ExistsOfferTx(txHash))
	{
		errorMessage = _("External Transaction ID specified was already used to pay for an offer");
		return true;
	}
	if(!dontaddtodb && !pescrowdb->WriteEscrowTx(theEscrow.vchEscrow, txHash))
	{
		errorMessage = _("Failed to External Transaction ID to DB");
		return false;
	}
	int precision = 2;
	string paymentOptionStr = GetPaymentOptionsString(theEscrow.nPaymentOption);

	CAmount nExpectedCommissionAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nCommission, nAcceptHeight, precision)*theEscrow.nQty;
	CAmount nExpectedAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), theOffer.GetPrice(foundEntry), nAcceptHeight, precision)*theEscrow.nQty;
	CAmount nEscrowFee = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nEscrowFee, nAcceptHeight, precision);
	int nExtFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr),  nAcceptHeight, precision);
	CAmount nEscrowTotal =  nExpectedAmount + nEscrowFee + (nExtFeePerByte*400);
	unsigned int nOutMultiSig = 0;
	CAmount nAmount = fundingTx.vout[nOutMultiSig].nValue;
	if(nAmount != nEscrowTotal)
	{
		errorMessage = _("Expected amount for external payment of escrow does not match what is held in escrow. Expected amount: ") +  boost::lexical_cast<string>(nEscrowTotal);
		return true;
	}
	CSyscoinAddress destaddy;
	CTxDestination payDest;
	if (!ExtractDestination(fundingTx.vout[nOutMultiSig].scriptPubKey, payDest))
	{
		errorMessage = _("Could not extract payment destination from external scriptPubKey");
		return true;
	}
	destaddy = CSyscoinAddress(payDest, PaymentOptionToAddressType(theEscrow.nPaymentOption));
	if(destaddy.ToString() != multisigaddress.ToString())
	{
		errorMessage = _("External escrow payment to invalid address");
		return true;
	}
	return true;
}
bool ValidatePayment(const CTransaction &escrowTx, const CEscrow& theEscrow, const COffer& theOffer, const COffer& linkOffer, const CAliasIndex &buyerAlias,const CAliasIndex &sellerAlias, const CAliasIndex &arbiterAlias, const uint64_t nHeight, const uint64_t nAcceptHeight, const bool &dontaddtodb, string& errorMessage)
{
	UniValue arrayParams(UniValue::VARR);
	UniValue arrayOfKeys(UniValue::VARR);

	// standard 2 of 3 multisig
	arrayParams.push_back(2);
	arrayOfKeys.push_back(HexStr(arbiterAlias.vchPubKey));
	arrayOfKeys.push_back(HexStr(sellerAlias.vchPubKey));
	arrayOfKeys.push_back(HexStr(buyerAlias.vchPubKey));
	arrayParams.push_back(arrayOfKeys);
	CScript inner = _createmultisig_redeemScript(arrayParams);
	CScriptID innerID(inner);
	CSyscoinAddress multisigaddress(innerID, PaymentOptionToAddressType(theEscrow.nPaymentOption));
	CAmount nCommission;
	COfferLinkWhitelistEntry foundEntry;
	if(theOffer.vchLinkOffer.empty())
	{
		theOffer.linkWhitelist.GetLinkEntryByHash(buyerAlias.vchAlias, foundEntry);
		nCommission = 0;
	}
	else
	{
		linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, foundEntry);
		nCommission = theOffer.GetPrice() - linkOffer.GetPrice(foundEntry);
	}
	if(!theEscrow.rawTx.empty())
	{
		bool noError = ValidateExternalPayment(theEscrow, theOffer, sellerAlias, nAcceptHeight, foundEntry, dontaddtodb, nCommission, multisigaddress, errorMessage);
		if(!noError)
			return false;
		else
			return true;
	}
	else
	{
		int precision=2;
		CAmount nExpectedCommissionAmount = nCommission*theEscrow.nQty;
		CAmount nExpectedAmount = theOffer.GetPrice(foundEntry)*theEscrow.nQty;
		float fEscrowFee = getEscrowFee(sellerAlias.vchAliasPeg, theOffer.sCurrencyCode, nAcceptHeight, precision);
		CAmount nEscrowFee = GetEscrowArbiterFee(nExpectedAmount, fEscrowFee);
		int nFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString("SYS"),  nAcceptHeight,precision);
		CAmount nEscrowTotal =  nExpectedAmount + nEscrowFee + (nFeePerByte*400);
		unsigned int nOutMultiSig = 0;
		CAmount nAmount = escrowTx.vout[nOutMultiSig].nValue;
		if(nAmount != nEscrowTotal)
		{
			errorMessage = _("Expected amount of escrow does not match what is held in escrow. Expected amount: ") +  boost::lexical_cast<string>(nEscrowTotal);
			return true;
		}
		CSyscoinAddress destaddy;
		CTxDestination payDest;
		if (!ExtractDestination(escrowTx.vout[nOutMultiSig].scriptPubKey, payDest))
		{
			errorMessage = _("Could not extract payment destination from scriptPubKey");
			return true;
		}
		destaddy = CSyscoinAddress(payDest, PaymentOptionToAddressType(theEscrow.nPaymentOption));
		if(destaddy.ToString() != multisigaddress.ToString())
		{
			errorMessage = _("Escrow payment to invalid address");
			return true;
		}
	}
	return true;
}
bool CheckEscrowInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, const CBlock* block, bool dontaddtodb) {
	if(!IsSys21Fork(nHeight))
		return true;
	if (tx.IsCoinBase())
		return true;
	const COutPoint *prevOutput = NULL;
	const CCoins *prevCoins;
	int prevAliasOp = 0;
	bool foundAlias = false;
	if (fDebug)
		LogPrintf("*** ESCROW %d %d %s %s\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			fJustCheck ? "JUSTCHECK" : "BLOCK");

    // Make sure escrow outputs are not spent by a regular transaction, or the escrow would be lost
    if (tx.nVersion != SYSCOIN_TX_VERSION)
	{
		errorMessage = "SYSCOIN_ESCROW_MESSAGE_ERROR: ERRCODE: 4000 - " + _("Non-Syscoin transaction found");
		return true;
	}
	 // unserialize escrow UniValue from txn, check for valid
    CEscrow theEscrow;
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	int nDataOut;
	if(GetSyscoinData(tx, vchData, vchHash, nDataOut) && !theEscrow.UnserializeFromData(vchData, vchHash))
	{
		theEscrow.SetNull();
	}
	if(theEscrow.IsNull())
	{
		if(fDebug)
			LogPrintf("SYSCOIN_ESCROW_CONSENSUS_ERROR: Null escrow, skipping...\n");
		return true;
	}
	vector<vector<unsigned char> > vvchPrevAliasArgs;
	if(fJustCheck)
	{
		if(vvchArgs.size() != 3)
		{
			errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4002 - " + _("Escrow arguments incorrect size");
			return error(errorMessage.c_str());
		}
		if(!theEscrow.IsNull())
		{
			if(vvchArgs.size() <= 2 || vchHash != vvchArgs[2])
			{
				errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4003 - " + _("Hash provided doesn't match the calculated hash of the data");
				return error(errorMessage.c_str());
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
			if(foundAlias)
				break;

			else if (!foundAlias && IsAliasOp(pop))
			{
				foundAlias = true;
				prevAliasOp = pop;
				vvchPrevAliasArgs = vvch;
			}
		}
	}

	vector<COffer> myVtxPos,myLinkVtxPos;
	CAliasIndex buyerAlias, sellerAlias, arbiterAlias;
	CTransaction aliasTx;
    COffer theOffer;
	string retError = "";
	CTransaction txOffer;
	int escrowOp = OP_ESCROW_ACTIVATE;
	bool bPaymentAck = false;
	COffer dbOffer;
	if(fJustCheck)
	{
		if (vvchArgs.empty() || vvchArgs[0].size() > MAX_GUID_LENGTH)
		{
			errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4004 - " + _("Escrow guid too big");
			return error(errorMessage.c_str());
		}
		if(theEscrow.vchRedeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
		{
			errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4005 - " + _("Escrow redeem script too long");
			return error(errorMessage.c_str());
		}
		if(theEscrow.feedback.size() > 0 && theEscrow.feedback[0].vchFeedback.size() > MAX_VALUE_LENGTH)
		{
			errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4006 - " + _("Feedback too long");
			return error(errorMessage.c_str());
		}
		if(theEscrow.feedback.size() > 1 && theEscrow.feedback[1].vchFeedback.size() > MAX_VALUE_LENGTH)
		{
			errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4007 - " + _("Feedback too long");
			return error(errorMessage.c_str());
		}
		if(theEscrow.vchOffer.size() > MAX_ID_LENGTH)
		{
			errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4008 - " + _("Escrow offer guid too long");
			return error(errorMessage.c_str());
		}
		if(!theEscrow.vchEscrow.empty() && theEscrow.vchEscrow != vvchArgs[0])
		{
			errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4009 - " + _("Escrow guid in data output doesn't match guid in transaction");
			return error(errorMessage.c_str());
		}
		switch (op) {
			case OP_ESCROW_ACTIVATE:
				if (theEscrow.bPaymentAck)
				{
					if(!IsAliasOp(prevAliasOp) || theEscrow.vchLinkAlias != vvchPrevAliasArgs[0] )
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4024 - " + _("Alias input mismatch");
						return error(errorMessage.c_str());
					}
				}
				else
				{
					if(!IsAliasOp(prevAliasOp) || theEscrow.vchBuyerAlias != vvchPrevAliasArgs[0] )
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4024 - " + _("Alias input mismatch");
						return error(errorMessage.c_str());
					}
					if(theEscrow.op != OP_ESCROW_ACTIVATE)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4010 - " + _("Invalid op, should be escrow activate");
						return error(errorMessage.c_str());
					}
				}
				if (theEscrow.vchEscrow != vvchArgs[0])
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4011 - " + _("Escrow Guid mismatch");
					return error(errorMessage.c_str());
				}
				if(!ValidatePaymentOptionsMask(theEscrow.nPaymentOption))
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 1018 - " + _("Invalid payment option");
					return error(errorMessage.c_str());
				}
				if (!theEscrow.rawTx.empty() && theEscrow.nPaymentOption == PAYMENTOPTION_SYS)
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4012 - " + _("External payment cannot be paid with SYS");
					return error(errorMessage.c_str());
				}
				if(!theEscrow.feedback.empty())
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4013 - " + _("Cannot leave feedback in escrow activation");
					return error(errorMessage.c_str());
				}
				break;
			case OP_ESCROW_RELEASE:
				if (vvchArgs.size() <= 1 || vvchArgs[1].size() > 1)
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4018 - " + _("Escrow release status too large");
					return error(errorMessage.c_str());
				}
				if(!theEscrow.feedback.empty())
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4019 - " + _("Cannot leave feedback in escrow release");
					return error(errorMessage.c_str());
				}
				if(vvchArgs[1] == vchFromString("1"))
				{
					if(theEscrow.op != OP_ESCROW_COMPLETE)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4021 - " + _("Invalid op, should be escrow complete");
						return error(errorMessage.c_str());
					}

				}
				else
				{
					if(theEscrow.op != OP_ESCROW_RELEASE)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4023 - " + _("Invalid op, should be escrow release");
						return error(errorMessage.c_str());
					}
				}

				break;
			case OP_ESCROW_COMPLETE:
				if(!IsAliasOp(prevAliasOp) || theEscrow.vchLinkAlias != vvchPrevAliasArgs[0] )
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4024 - " + _("Alias input mismatch");
					return error(errorMessage.c_str());
				}
				if (theEscrow.op != OP_ESCROW_COMPLETE)
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4025 - " + _("Invalid op, should be escrow complete");
					return error(errorMessage.c_str());
				}
				if(theEscrow.feedback.empty())
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4026 - " + _("Feedback must leave a message");
					return error(errorMessage.c_str());
				}

				if(theEscrow.op != OP_ESCROW_COMPLETE)
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4027 - " + _("Invalid op, should be escrow complete");
					return error(errorMessage.c_str());
				}
				break;
			case OP_ESCROW_REFUND:
				if(!IsAliasOp(prevAliasOp) || theEscrow.vchLinkAlias != vvchPrevAliasArgs[0] )
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4024 - " + _("Alias input mismatch");
					return error(errorMessage.c_str());
				}
				if (vvchArgs.size() <= 1 || vvchArgs[1].size() > 1)
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4029 - " + _("Escrow refund status too large");
					return error(errorMessage.c_str());
				}
				if (theEscrow.vchEscrow != vvchArgs[0])
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4031 - " + _("Guid mismatch");
					return error(errorMessage.c_str());
				}
				if(vvchArgs[1] == vchFromString("1"))
				{
					if(theEscrow.op != OP_ESCROW_COMPLETE)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4033 - " + _("Invalid op, should be escrow complete");
						return error(errorMessage.c_str());
					}
				}
				else
				{
					if(theEscrow.op != OP_ESCROW_REFUND)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4035 - " + _("Invalid op, should be escrow refund");
						return error(errorMessage.c_str());
					}
				}
				// Check input
				if(!theEscrow.feedback.empty())
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4036 - " + _("Cannot leave feedback in escrow refund");
					return error(errorMessage.c_str());
				}



				break;
			default:
				errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4037 - " + _("Escrow transaction has unknown op");
				return error(errorMessage.c_str());
		}
	}



    if (!fJustCheck ) {
		if(op == OP_ESCROW_ACTIVATE)
		{
			if (!theEscrow.bPaymentAck)
			{
				if(!GetTxOfAlias(theEscrow.vchBuyerAlias, buyerAlias, aliasTx))
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4038 - " + _("Cannot find buyer alias. It may be expired");
					return true;
				}
				if(!GetTxOfAlias(theEscrow.vchArbiterAlias, arbiterAlias, aliasTx))
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4040 - " + _("Cannot find arbiter alias. It may be expired");
					return true;
				}
				if(!GetTxOfAlias(theEscrow.vchSellerAlias, sellerAlias, aliasTx))
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4039 - " + _("Cannot find seller alias. It may be expired");
					return true;
				}
			}
		}
		vector<CEscrow> vtxPos;
		// make sure escrow settings don't change (besides rawTx) outside of activation
		if(op != OP_ESCROW_ACTIVATE || theEscrow.bPaymentAck)
		{
			// save serialized escrow for later use
			CEscrow serializedEscrow = theEscrow;
			CTransaction escrowTx;
			if(!GetTxAndVtxOfEscrow(vvchArgs[0], theEscrow, escrowTx, vtxPos))
			{
				errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4041 - " + _("Failed to read from escrow DB");
				return true;
			}
			if(serializedEscrow.bPaymentAck && theEscrow.bPaymentAck)
			{
				errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4041 - " + _("Escrow already acknowledged");
				return true;
			}
			// make sure we have found this escrow in db
			if(!vtxPos.empty())
			{
				if (theEscrow.vchEscrow != vvchArgs[0])
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4042 - " + _("Escrow Guid mismatch");
					serializedEscrow = theEscrow;
				}

				// these are the only settings allowed to change outside of activate
				if(!serializedEscrow.rawTx.empty() && op != OP_ESCROW_ACTIVATE)
					theEscrow.rawTx = serializedEscrow.rawTx;
				escrowOp = serializedEscrow.op;
				if(op == OP_ESCROW_ACTIVATE && serializedEscrow.bPaymentAck)
				{
					if(serializedEscrow.vchLinkAlias != theEscrow.vchSellerAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4045 - " + _("Only seller can acknowledge an escrow payment");
						return true;
					}
					theEscrow.bPaymentAck = true;
				}
				if(op == OP_ESCROW_REFUND && vvchArgs[1] == vchFromString("0"))
				{
					CAliasIndex alias;
					if(!GetTxOfAlias(theEscrow.vchSellerAlias, alias, aliasTx))
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4039 - " + _("Cannot find seller alias. It may be expired");
						return true;
					}
					if(!GetTxOfAlias(theEscrow.vchArbiterAlias, alias, aliasTx))
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4040 - " + _("Cannot find arbiter alias. It may be expired");
						return true;
					}

					if(theEscrow.op == OP_ESCROW_COMPLETE)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4043 - " + _("Can only refund an active escrow");
						serializedEscrow = theEscrow;
					}
					else if(theEscrow.op == OP_ESCROW_RELEASE)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4044 - " + _("Cannot refund an escrow that is already released");
						serializedEscrow = theEscrow;
					}
					else if(serializedEscrow.vchLinkAlias != theEscrow.vchSellerAlias && serializedEscrow.vchLinkAlias != theEscrow.vchArbiterAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4045 - " + _("Only arbiter or seller can initiate an escrow refund");
						serializedEscrow = theEscrow;
					}
					// only the arbiter can re-refund an escrow
					else if(theEscrow.op == OP_ESCROW_REFUND && serializedEscrow.vchLinkAlias != theEscrow.vchArbiterAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4046 - " + _("Only arbiter can refund an escrow after it has already been refunded");
						serializedEscrow = theEscrow;
					}
					// refund qty
					int nQty = dbOffer.nQty;
					COffer myLinkOffer;
					if (pofferdb->ExistsOffer(dbOffer.vchLinkOffer)) {
						if (pofferdb->ReadOffer(dbOffer.vchLinkOffer, myLinkVtxPos) && !myLinkVtxPos.empty())
						{
							myLinkOffer = myLinkVtxPos.back();
							nQty = myLinkOffer.nQty;
						}
					}
					if(nQty != -1)
					{
						nQty += theEscrow.nQty;
						if (!myLinkOffer.IsNull())
						{
							myLinkOffer.nQty = nQty;
							myLinkOffer.nSold--;
							myLinkOffer.PutToOfferList(myLinkVtxPos);
							if (!dontaddtodb && !pofferdb->WriteOffer(dbOffer.vchLinkOffer, myLinkVtxPos))
							{
								errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4072 - " + _("Failed to write to offer link to DB");
								return true;
							}
						}
						else
						{
							dbOffer.nQty = nQty;
							dbOffer.nSold--;
							dbOffer.PutToOfferList(myVtxPos);
							if (!dontaddtodb && !pofferdb->WriteOffer(theEscrow.vchOffer, myVtxPos))
							{
								errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4075 - " + _("Failed to write to offer to DB");
								return true;
							}
						}
					}
				}
				else if(op == OP_ESCROW_REFUND && vvchArgs[1] == vchFromString("1"))
				{
					if(theEscrow.op != OP_ESCROW_REFUND)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4052 - " + _("Can only claim a refunded escrow");
						serializedEscrow = theEscrow;
					}
					else if(!serializedEscrow.redeemTxId.IsNull())
						theEscrow.redeemTxId = serializedEscrow.redeemTxId;
					else if(serializedEscrow.vchLinkAlias != theEscrow.vchBuyerAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4051 - " + _("Only buyer can claim an escrow refund");
						serializedEscrow = theEscrow;
					}
				}
				else if(op == OP_ESCROW_RELEASE && vvchArgs[1] == vchFromString("0"))
				{
					if(!GetTxOfAlias(theEscrow.vchBuyerAlias, alias, aliasTx))
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4038 - " + _("Cannot find buyer alias. It may be expired");
						return true;
					}
					if(!GetTxOfAlias(theEscrow.vchArbiterAlias, alias, aliasTx))
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4040 - " + _("Cannot find arbiter alias. It may be expired");
						return true;
					}
					if(theEscrow.op == OP_ESCROW_COMPLETE)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4052 - " + _("Can only release an active escrow");
						serializedEscrow = theEscrow;
					}
					else if(theEscrow.op == OP_ESCROW_REFUND)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4053 - " + _("Cannot release an escrow that is already refunded");
						serializedEscrow = theEscrow;
					}
					else if(serializedEscrow.vchLinkAlias != theEscrow.vchBuyerAlias && serializedEscrow.vchLinkAlias != theEscrow.vchArbiterAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4054 - " + _("Only arbiter or buyer can initiate an escrow release");
						serializedEscrow = theEscrow;
					}
					// only the arbiter can re-release an escrow
					else if(theEscrow.op == OP_ESCROW_RELEASE && serializedEscrow.vchLinkAlias != theEscrow.vchArbiterAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4055 - " + _("Only arbiter can release an escrow after it has already been released");
						serializedEscrow = theEscrow;
					}
				}
				else if(op == OP_ESCROW_RELEASE && vvchArgs[1] == vchFromString("1"))
				{
					if(theEscrow.op != OP_ESCROW_RELEASE)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4052 - " + _("Can only claim a released escrow");
						serializedEscrow = theEscrow;
					}
					else if(!serializedEscrow.redeemTxId.IsNull())
						theEscrow.redeemTxId = serializedEscrow.redeemTxId;
					else if(serializedEscrow.vchLinkAlias != theEscrow.vchSellerAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4056 - " + _("Only seller can claim an escrow release");
						serializedEscrow = theEscrow;
					}
				}
				else if(op == OP_ESCROW_COMPLETE)
				{
					if(serializedEscrow.feedback.size() != 2)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4057 - " + _("Invalid number of escrow feedbacks provided");
						serializedEscrow = theEscrow;
					}
					if(serializedEscrow.feedback[0].nFeedbackUserFrom ==  serializedEscrow.feedback[0].nFeedbackUserTo ||
						serializedEscrow.feedback[1].nFeedbackUserFrom ==  serializedEscrow.feedback[1].nFeedbackUserTo)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4058 - " + _("Cannot send yourself feedback");
						serializedEscrow = theEscrow;
					}
					else if(serializedEscrow.feedback[0].vchFeedback.size() <= 0 && serializedEscrow.feedback[1].vchFeedback.size() <= 0)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4059 - " + _("Feedback must leave a message");
						serializedEscrow = theEscrow;
					}
					else if(serializedEscrow.feedback[0].nRating > 5 || serializedEscrow.feedback[1].nRating > 5)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4060 - " + _("Invalid rating, must be less than or equal to 5 and greater than or equal to 0");
						serializedEscrow = theEscrow;
					}
					else if((serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER || serializedEscrow.feedback[1].nFeedbackUserFrom == FEEDBACKBUYER) && serializedEscrow.vchLinkAlias != theEscrow.vchBuyerAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4061 - " + _("Only buyer can leave this feedback");
						serializedEscrow = theEscrow;
					}
					else if((serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER || serializedEscrow.feedback[1].nFeedbackUserFrom == FEEDBACKSELLER) && serializedEscrow.vchLinkAlias != theEscrow.vchSellerAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4062 - " + _("Only seller can leave this feedback");
						serializedEscrow = theEscrow;
					}
					else if((serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKARBITER || serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKARBITER) && serializedEscrow.vchLinkAlias != theEscrow.vchArbiterAlias)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4063 - " + _("Only arbiter can leave this feedback");
						serializedEscrow = theEscrow;
					}
					serializedEscrow.feedback[0].nHeight = nHeight;
					serializedEscrow.feedback[0].txHash = tx.GetHash();
					serializedEscrow.feedback[1].nHeight = nHeight;
					serializedEscrow.feedback[1].txHash = tx.GetHash();
					int numBuyerRatings, numSellerRatings, numArbiterRatings, feedbackBuyerCount, feedbackSellerCount, feedbackArbiterCount;
					FindFeedback(theEscrow.feedback, numBuyerRatings, numSellerRatings, numArbiterRatings, feedbackBuyerCount, feedbackSellerCount, feedbackArbiterCount);

					// has this user already rated?
					if(numBuyerRatings > 0)
					{
						if(serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER)
							serializedEscrow.feedback[0].nRating = 0;
						if(serializedEscrow.feedback[1].nFeedbackUserFrom == FEEDBACKBUYER)
							serializedEscrow.feedback[1].nRating = 0;
					}
					if(numSellerRatings > 0)
					{
						if(serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER)
							serializedEscrow.feedback[0].nRating = 0;
						if(serializedEscrow.feedback[1].nFeedbackUserFrom == FEEDBACKSELLER)
							serializedEscrow.feedback[1].nRating = 0;
					}
					if(numArbiterRatings > 0)
					{
						if(serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKARBITER)
							serializedEscrow.feedback[0].nRating = 0;
						if(serializedEscrow.feedback[1].nFeedbackUserFrom == FEEDBACKARBITER)
							serializedEscrow.feedback[1].nRating = 0;
					}

					if(feedbackBuyerCount >= 10 && (serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER || serializedEscrow.feedback[1].nFeedbackUserFrom == FEEDBACKBUYER))
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4064 - " + _("Cannot exceed 10 buyer feedbacks");
						serializedEscrow = theEscrow;
					}
					else if(feedbackSellerCount >= 10 && (serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER || serializedEscrow.feedback[1].nFeedbackUserFrom == FEEDBACKSELLER))
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4065 - " + _("Cannot exceed 10 seller feedbacks");
						serializedEscrow = theEscrow;
					}
					else if(feedbackArbiterCount >= 10 && (serializedEscrow.feedback[0].nFeedbackUserFrom == FEEDBACKARBITER || serializedEscrow.feedback[1].nFeedbackUserFrom == FEEDBACKARBITER))
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4066 - " + _("Cannot exceed 10 arbiter feedbacks");
						serializedEscrow = theEscrow;
					}
					if(!dontaddtodb)
						HandleEscrowFeedback(serializedEscrow, theEscrow, vtxPos);
					return true;
				}
			}
			else
			{
				errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4067 - " + _("Escrow not found when trying to update");
				serializedEscrow = theEscrow;
			}

		}
		else
		{
			COffer myLinkOffer;
			if (pescrowdb->ExistsEscrow(vvchArgs[0]))
			{
				errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4068 - " + _("Escrow already exists");
				return true;
			}
			if(theEscrow.nQty <= 0)
				theEscrow.nQty = 1;

			if (GetTxAndVtxOfOffer( theEscrow.vchOffer, dbOffer, txOffer, myVtxPos))
			{
				if(dbOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(dbOffer.sCategory), "wanted"))
				{
					errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4071 - " + _("Cannot purchase a wanted offer");
					return true;
				}
				int nQty = dbOffer.nQty;
				// if this is a linked offer we must update the linked offer qty
				if (pofferdb->ExistsOffer(dbOffer.vchLinkOffer)) {
					if (pofferdb->ReadOffer(dbOffer.vchLinkOffer, myLinkVtxPos) && !myLinkVtxPos.empty())
					{
						myLinkOffer = myLinkVtxPos.back();
						nQty = myLinkOffer.nQty;
					}
				}
				if(nQty != -1)
				{
					if(theEscrow.nQty > nQty)
					{
						errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 1105 - " + _("Not enough quantity left in this offer for this purchase");
						return true;
					}
					nQty -= theEscrow.nQty;
					if (!myLinkOffer.IsNull())
					{
						myLinkOffer.nQty = nQty;
						myLinkOffer.nSold++;
						myLinkOffer.PutToOfferList(myLinkVtxPos);
						if (!dontaddtodb && !pofferdb->WriteOffer(dbOffer.vchLinkOffer, myLinkVtxPos))
						{
							errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4072 - " + _("Failed to write to offer link to DB");
							return true;
						}
					}
					else
					{
						dbOffer.nQty = nQty;
						dbOffer.nSold++;
						dbOffer.PutToOfferList(myVtxPos);
						if (!dontaddtodb && !pofferdb->WriteOffer(theEscrow.vchOffer, myVtxPos))
						{
							errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4075 - " + _("Failed to write to offer to DB");
							return true;
						}
					}
				}
			}
			else
			{
				errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4076 - " + _("Cannot find offer for this escrow. It may be expired");
				return true;
			}
			if(!theOffer.vchLinkOffer.empty() && myLinkOffer.IsNull())
			{
				errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4076 - " + _("Cannot find linked offer for this escrow");
				return true;
			}
			if(!myLinkOffer.IsNull())
			{
				myLinkOffer.nHeight = theEscrow.nAcceptHeight;
				myLinkOffer.GetOfferFromList(myLinkVtxPos);
			}
			dbOffer.nHeight = theEscrow.nAcceptHeight;
			dbOffer.GetOfferFromList(myVtxPos);
			bool noError = ValidatePayment(tx, theEscrow, dbOffer, myLinkOffer, buyerAlias, sellerAlias, arbiterAlias, nHeight, theEscrow.nAcceptHeight, dontaddtodb, errorMessage);
			if(!errorMessage.empty())
			{
				errorMessage =  "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4069 - " + errorMessage;
				if(!noError)
					return error(errorMessage.c_str());
				else
					return true;
			}
		}
		

        // set the escrow's txn-dependent values
		if(!bPaymentAck)
			theEscrow.op = escrowOp;
		theEscrow.txHash = tx.GetHash();
		theEscrow.nHeight = nHeight;
		PutToEscrowList(vtxPos, theEscrow);
        // write escrow

        if (!dontaddtodb && !pescrowdb->WriteEscrow(vvchArgs[0], vtxPos))
		{
			errorMessage = "SYSCOIN_ESCROW_CONSENSUS_ERROR: ERRCODE: 4077 - " + _("Failed to write to escrow DB");
			return true;
		}
		if(fDebug)
			LogPrintf( "CONNECTED ESCROW: op=%s escrow=%s hash=%s height=%d\n",
                escrowFromOp(op).c_str(),
                stringFromVch(vvchArgs[0]).c_str(),
                tx.GetHash().ToString().c_str(),
                nHeight);
	}
    return true;
}
void HandleEscrowFeedback(const CEscrow& serializedEscrow, CEscrow& dbEscrow, vector<CEscrow> &vtxPos)
{
	for(int i =0;i<serializedEscrow.feedback.size();i++)
	{
		if(serializedEscrow.feedback[i].nRating > 0)
		{
			CSyscoinAddress address;
			if(serializedEscrow.feedback[i].nFeedbackUserTo == FEEDBACKBUYER)
				address = CSyscoinAddress(stringFromVch(dbEscrow.vchBuyerAlias));
			else if(serializedEscrow.feedback[i].nFeedbackUserTo == FEEDBACKSELLER)
				address = CSyscoinAddress(stringFromVch(dbEscrow.vchSellerAlias));
			else if(serializedEscrow.feedback[i].nFeedbackUserTo == FEEDBACKARBITER)
				address = CSyscoinAddress(stringFromVch(dbEscrow.vchArbiterAlias));
			if(address.IsValid() && address.isAlias)
			{
				vector<CAliasIndex> vtxPos;
				const vector<unsigned char> &vchAlias = vchFromString(address.aliasName);
				if (paliasdb->ReadAlias(vchAlias, vtxPos) && !vtxPos.empty())
				{

					CAliasIndex alias = vtxPos.back();
					if(serializedEscrow.feedback[i].nFeedbackUserTo == FEEDBACKBUYER)
					{
						alias.nRatingCountAsBuyer++;
						alias.nRatingAsBuyer += serializedEscrow.feedback[i].nRating;
					}
					else if(serializedEscrow.feedback[i].nFeedbackUserTo == FEEDBACKSELLER)
					{
						alias.nRatingCountAsSeller++;
						alias.nRatingAsSeller += serializedEscrow.feedback[i].nRating;
					}
					else if(serializedEscrow.feedback[i].nFeedbackUserTo == FEEDBACKARBITER)
					{
						alias.nRatingCountAsArbiter++;
						alias.nRatingAsArbiter += serializedEscrow.feedback[i].nRating;
					}


					PutToAliasList(vtxPos, alias);
					CSyscoinAddress multisigAddress;
					alias.GetAddress(&multisigAddress);
					paliasdb->WriteAlias(vchAlias, vchFromString(address.ToString()), vchFromString(multisigAddress.ToString()), vtxPos);
				}
			}

		}
		dbEscrow.feedback.push_back(serializedEscrow.feedback[i]);
	}
	PutToEscrowList(vtxPos, dbEscrow);
	pescrowdb->WriteEscrow(dbEscrow.vchEscrow, vtxPos);
}
UniValue generateescrowmultisig(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 4 ||  params.size() > 5)
        throw runtime_error(
		"generateescrowmultisig <buyer> <offer guid> <qty> <arbiter> [payment option=SYS]\n"
                        + HelpRequiringPassphrase());

	vector<unsigned char> vchBuyer = vchFromValue(params[0]);
	vector<unsigned char> vchOffer = vchFromValue(params[1]);
	unsigned int nQty = 1;

	try {
		nQty = boost::lexical_cast<unsigned int>(params[2].get_str());
	} catch (std::exception &e) {
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4500 - " + _("Invalid quantity value. Quantity must be less than 4294967296."));
	}
	vector<unsigned char> vchArbiter = vchFromValue(params[3]);
	// payment options - get payment options string if specified otherwise default to SYS
	string paymentOptions = "SYS";
	if(params.size() >= 5 && !params[4].get_str().empty() && params[4].get_str() != "NONE")
	{
		paymentOptions = params[4].get_str();
	}
	// payment options - validate payment options string
	if(!ValidatePaymentOptionsString(paymentOptions))
	{
		string err = "SYSCOIN_ESCROW_RPC_ERROR ERRCODE: 1504 - " + _("Could not validate the payment options value");
		throw runtime_error(err.c_str());
	}

	CAliasIndex arbiteralias;
	CTransaction arbiteraliastx;
	if (!GetTxOfAlias(vchArbiter, arbiteralias, arbiteraliastx))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4501 - " + _("Failed to read arbiter alias from DB"));

	CAliasIndex buyeralias;
	CTransaction buyeraliastx;
	if (!GetTxOfAlias(vchBuyer, buyeralias, buyeraliastx))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4502 - " + _("Failed to read arbiter alias from DB"));

	CTransaction txOffer, txAlias;
	vector<COffer> offerVtxPos;
	COffer theOffer, linkedOffer;
	if (!GetTxAndVtxOfOffer( vchOffer, theOffer, txOffer, offerVtxPos, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4503 - " + _("Could not find an offer with this identifier"));

	CAliasIndex selleralias;
	if (!GetTxOfAlias( theOffer.vchAlias, selleralias, txAlias, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4504 - " + _("Could not find seller alias with this identifier"));

	COfferLinkWhitelistEntry foundEntry;
	if(!theOffer.vchLinkOffer.empty())
	{
		CTransaction tmpTx;
		vector<COffer> offerTmpVtxPos;
		if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkedOffer, tmpTx, offerTmpVtxPos, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4505 - " + _("Trying to accept a linked offer but could not find parent offer"));

		CAliasIndex theLinkedAlias;
		CTransaction txLinkedAlias;
		if (!GetTxOfAlias( linkedOffer.vchAlias, theLinkedAlias, txLinkedAlias, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4506 - " + _("Could not find an alias with this identifier"));


		selleralias = theLinkedAlias;
	}
	else
	{
		// if offer is not linked, look for a discount for the buyer
		theOffer.linkWhitelist.GetLinkEntryByHash(buyeralias.vchAlias, foundEntry);

	}
	CPubKey ArbiterPubKey(arbiteralias.vchPubKey);
	CPubKey SellerPubKey(selleralias.vchPubKey);
	CPubKey BuyerPubKey(buyeralias.vchPubKey);
	CScript scriptArbiter = GetScriptForDestination(ArbiterPubKey.GetID());
	CScript scriptSeller = GetScriptForDestination(SellerPubKey.GetID());
	CScript scriptBuyer = GetScriptForDestination(BuyerPubKey.GetID());
	UniValue arrayParams(UniValue::VARR);
	UniValue arrayOfKeys(UniValue::VARR);

	// standard 2 of 3 multisig
	arrayParams.push_back(2);
	arrayOfKeys.push_back(HexStr(arbiteralias.vchPubKey));
	arrayOfKeys.push_back(HexStr(selleralias.vchPubKey));
	arrayOfKeys.push_back(HexStr(buyeralias.vchPubKey));
	arrayParams.push_back(arrayOfKeys);
	UniValue resCreate;
	CScript redeemScript;
	try
	{
		resCreate = tableRPC.execute("createmultisig", arrayParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resCreate.isObject())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4507 - " + _("Could not create escrow transaction: Invalid response from createescrow"));

	int precision = 2;
	float fEscrowFee = getEscrowFee(selleralias.vchAliasPeg, vchFromString(paymentOptions), chainActive.Tip()->nHeight, precision);
	CAmount nTotal = theOffer.GetPrice(foundEntry)*nQty;
	CAmount nEscrowFee = GetEscrowArbiterFee(nTotal, fEscrowFee);
	CAmount nExtFee = convertSyscoinToCurrencyCode(selleralias.vchAliasPeg, vchFromString(paymentOptions), nEscrowFee, chainActive.Tip()->nHeight, precision);
	CAmount nExtTotal = convertSyscoinToCurrencyCode(selleralias.vchAliasPeg, vchFromString(paymentOptions), theOffer.GetPrice(foundEntry), chainActive.Tip()->nHeight, precision)*nQty;
	int nExtFeePerByte = getFeePerByte(selleralias.vchAliasPeg, vchFromString(paymentOptions), chainActive.Tip()->nHeight, precision);
	// multisig spend is about 400 bytes
	nExtTotal += nExtFee + (nExtFeePerByte*400);
	resCreate.push_back(Pair("total", ValueFromAmount(nExtTotal)));
	resCreate.push_back(Pair("height", chainActive.Tip()->nHeight));
	return resCreate;
}

UniValue escrownew(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 5 ||  params.size() > 9)
        throw runtime_error(
		"escrownew <alias> <offer> <quantity> <message> <arbiter alias> [extTx] [payment option=SYS] [redeemScript] [height]\n"
						"<alias> An alias you own.\n"
                        "<offer> GUID of offer that this escrow is managing.\n"
                        "<quantity> Quantity of items to buy of offer.\n"
						"<message> Delivery details to seller.\n"
						"<arbiter alias> Alias of Arbiter.\n"
						"<extTx> If paid in another coin enter raw external input transaction.\n"
						"<paymentOption> If extTx is defined, specify a valid payment option used to make payment. Default is SYS.\n"
						"<redeemScript> If paid in external chain, enter redeemScript that generateescrowmultisig returns\n"
						"<height> If paid in extneral chain, enter height that generateescrowmultisig returns\n"
                        + HelpRequiringPassphrase());
	vector<unsigned char> vchAlias = vchFromValue(params[0]);
	vector<unsigned char> vchOffer = vchFromValue(params[1]);
	uint64_t nHeight = chainActive.Tip()->nHeight;
	string strArbiter = params[4].get_str();
	boost::algorithm::to_lower(strArbiter);
	// check for alias existence in DB
	CAliasIndex arbiteralias;
	CTransaction aliastx, buyeraliastx;
	if (!GetTxOfAlias(vchFromString(strArbiter), arbiteralias, aliastx))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4508 - " + _("Failed to read arbiter alias from DB"));


	vector<unsigned char> vchMessage = vchFromValue(params[3]);
	vector<unsigned char> vchExtTx;
	if(params.size() >= 6)
		vchExtTx = vchFromValue(params[5]);
	// payment options - get payment options string if specified otherwise default to SYS
	string paymentOptions = "SYS";
	if(params.size() >= 7 && !params[6].get_str().empty() && params[6].get_str() != "NONE")
	{
		paymentOptions = params[6].get_str();
	}
	// payment options - validate payment options string
	if(!ValidatePaymentOptionsString(paymentOptions))
	{
		// TODO change error number to something unique
		string err = "SYSCOIN_ESCROW_RPC_ERROR ERRCODE: 1504 - " + _("Could not validate the payment options value");
		throw runtime_error(err.c_str());
	}
		// payment options - and convert payment options string to a bitmask for the txn
	unsigned char paymentOptionsMask = (unsigned char) GetPaymentOptionsMaskFromString(paymentOptions);
	vector<unsigned char> vchRedeemScript;
	if(params.size() >= 8)
		vchRedeemScript = vchFromValue(params[7]);
	if(params.size() >= 9)
		nHeight = boost::lexical_cast<uint64_t>(params[8].get_str());

	unsigned int nQty = 1;

	try {
		nQty = boost::lexical_cast<unsigned int>(params[2].get_str());
	} catch (std::exception &e) {
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4510 - " + _("Invalid quantity value. Quantity must be less than 4294967296."));
	}

    if (vchMessage.size() <= 0)
        vchMessage = vchFromString("ESCROW");


	CAliasIndex buyeralias;
	if (!GetTxOfAlias(vchAlias, buyeralias, buyeraliastx))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4511 - " + _("Could not find buyer alias with this name"));

	CPubKey buyerKey(buyeralias.vchPubKey);

	COffer theOffer, linkedOffer;

	CTransaction txOffer, txAlias;
	vector<COffer> offerVtxPos;
	if (!GetTxAndVtxOfOffer( vchOffer, theOffer, txOffer, offerVtxPos, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4512 - " + _("Could not find an offer with this identifier"));

	CAliasIndex selleralias;
	if (!GetTxOfAlias( theOffer.vchAlias, selleralias, txAlias, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4513 - " + _("Could not find seller alias with this identifier"));

	if(theOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(theOffer.sCategory), "wanted"))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4515 - " + _("Cannot purchase a wanted offer"));

	const CWalletTx *wtxAliasIn = NULL;

	CScript scriptPubKeyAlias, scriptPubKeyAliasOrig;
	COfferLinkWhitelistEntry foundEntry;
	if(!theOffer.vchLinkOffer.empty())
	{

		CTransaction tmpTx;
		vector<COffer> offerTmpVtxPos;
		if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkedOffer, tmpTx, offerTmpVtxPos, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4516 - " + _("Trying to accept a linked offer but could not find parent offer"));

		CAliasIndex theLinkedAlias;
		CTransaction txLinkedAlias;
		if (!GetTxOfAlias( linkedOffer.vchAlias, theLinkedAlias, txLinkedAlias, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4517 - " + _("Could not find an alias with this identifier"));
		if(linkedOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(linkedOffer.sCategory), "wanted"))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4518 - " + _("Cannot purchase a wanted offer"));

		selleralias = theLinkedAlias;
	}

	if(!IsSyscoinTxMine(buyeraliastx, "alias"))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the buyer alias to complete this transaction"));
	wtxAliasIn = pwalletMain->GetWalletTx(buyeraliastx.GetHash());
	scriptPubKeyAliasOrig = GetScriptForDestination(buyerKey.GetID());
	if(buyeralias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyAliasOrig = CScript(buyeralias.multiSigInfo.vchRedeemScript.begin(), buyeralias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << buyeralias.vchAlias  << buyeralias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyAliasOrig;


    // gather inputs
	vector<unsigned char> vchEscrow = vchFromString(GenerateSyscoinGuid());

    // this is a syscoin transaction
    CWalletTx wtx;
	EnsureWalletIsUnlocked();
    CScript scriptPubKey, scriptPubKeyBuyer, scriptPubKeySeller, scriptPubKeyArbiter,scriptBuyer, scriptSeller,scriptArbiter;

	string strCipherText = "";
	// encrypt to offer owner
	if(!EncryptMessage(selleralias.vchPubKey, vchMessage, strCipherText))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4519 - " + _("Could not encrypt message to seller"));

	if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4520 - " + _("Payment message length cannot exceed 1023 bytes"));

	CPubKey ArbiterPubKey(arbiteralias.vchPubKey);
	CPubKey SellerPubKey(selleralias.vchPubKey);
	CPubKey BuyerPubKey(buyeralias.vchPubKey);

	scriptArbiter= GetScriptForDestination(ArbiterPubKey.GetID());
	scriptSeller= GetScriptForDestination(SellerPubKey.GetID());
	scriptBuyer= GetScriptForDestination(BuyerPubKey.GetID());
	vector<unsigned char> redeemScript;
	if(vchRedeemScript.empty())
	{
		UniValue arrayParams(UniValue::VARR);
		arrayParams.push_back(stringFromVch(buyeralias.vchAlias));
		arrayParams.push_back(stringFromVch(vchOffer));
		arrayParams.push_back( boost::lexical_cast<string>(nQty));
		arrayParams.push_back(stringFromVch(arbiteralias.vchAlias));
		UniValue resCreate;
		try
		{
			resCreate = tableRPC.execute("generateescrowmultisig", arrayParams);
		}
		catch (UniValue& objError)
		{
			throw runtime_error(find_value(objError, "message").get_str());
		}
		if (!resCreate.isObject())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4521 - " + _("Could not generate escrow multisig address: Invalid response from generateescrowmultisig"));
		const UniValue &o = resCreate.get_obj();
		const UniValue& redeemScript_value = find_value(o, "redeemScript");
		if (redeemScript_value.isStr())
		{
			redeemScript = ParseHex(redeemScript_value.get_str());
		}
		else
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4522 - " + _("Could not create escrow transaction: could not find redeem script in response"));
	}
	else
	{
			redeemScript = ParseHex(stringFromVch(vchRedeemScript));
	}
	scriptPubKey = CScript(redeemScript.begin(), redeemScript.end());
	int precision = 2;
	// send to escrow address
	CAmount nTotal = theOffer.GetPrice(foundEntry)*nQty;
	float fEscrowFee = getEscrowFee(selleralias.vchAliasPeg, theOffer.sCurrencyCode, chainActive.Tip()->nHeight, precision);
	CAmount nEscrowFee = GetEscrowArbiterFee(nTotal, fEscrowFee);
	int nFeePerByte = getFeePerByte(selleralias.vchAliasPeg, vchFromString("SYS"), chainActive.Tip()->nHeight,precision);

	vector<CRecipient> vecSend;
	CAmount nAmountWithFee = nTotal+nEscrowFee+(nFeePerByte*400);
	CWalletTx escrowWtx;
	CRecipient recipientEscrow  = {scriptPubKey, nAmountWithFee, false};
	if(vchExtTx.empty())
		vecSend.push_back(recipientEscrow);

	// send to seller/arbiter so they can track the escrow through GUI
    // build escrow
    CEscrow newEscrow;
	newEscrow.op = OP_ESCROW_ACTIVATE;
	newEscrow.vchEscrow = vchEscrow;
	newEscrow.vchBuyerAlias = buyeralias.vchAlias;
	newEscrow.vchArbiterAlias = arbiteralias.vchAlias;
	newEscrow.vchRedeemScript = redeemScript;
	newEscrow.vchOffer = vchOffer;
	newEscrow.vchSellerAlias = selleralias.vchAlias;
	newEscrow.vchPaymentMessage = vchFromString(strCipherText);
	newEscrow.nQty = nQty;
	newEscrow.rawTx = vchExtTx;
	newEscrow.nPaymentOption = paymentOptionsMask;
	newEscrow.nHeight = nHeight;
	newEscrow.nAcceptHeight = chainActive.Tip()->nHeight;

	const vector<unsigned char> &data = newEscrow.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashEscrow = vchFromValue(hash.GetHex());
	scriptPubKeyBuyer << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
	scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow  << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
	scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
	scriptPubKeySeller += scriptSeller;
	scriptPubKeyArbiter += scriptArbiter;
	scriptPubKeyBuyer += scriptBuyer;


	// send the tranasction

	CRecipient recipientArbiter;
	CreateRecipient(scriptPubKeyArbiter, recipientArbiter);
	vecSend.push_back(recipientArbiter);
	CRecipient recipientSeller;
	CreateRecipient(scriptPubKeySeller, recipientSeller);
	vecSend.push_back(recipientSeller);
	CRecipient recipientBuyer;
	CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
	vecSend.push_back(recipientBuyer);

	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);


	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, buyeralias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneySyscoin(vecSend,recipientBuyer.nAmount+recipientArbiter.nAmount+recipientSeller.nAmount+aliasRecipient.nAmount+recipientEscrow.nAmount+fee.nAmount, false, wtx, wtxAliasIn, buyeralias.multiSigInfo.vchAliases.size() > 0);
	UniValue res(UniValue::VARR);
	if(buyeralias.multiSigInfo.vchAliases.size() > 0)
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
			res.push_back(stringFromVch(vchEscrow));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchEscrow));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchEscrow));
	}
	return res;
}
UniValue escrowrelease(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
		"escrowrelease <escrow guid> <user role>\n"
                        "Releases escrow funds to seller, seller needs to sign the output transaction and send to the network. User role represents either 'buyer' or 'arbiter'\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
	string role = params[1].get_str();
    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
	vector<CEscrow> vtxPos;
    if (!GetTxAndVtxOfEscrow( vchEscrow,
		escrow, tx, vtxPos))
        throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4523 - " + _("Could not find a escrow with this key"));

	CAliasIndex sellerAlias, sellerAliasLatest, buyerAlias, buyerAliasLatest, arbiterAlias, arbiterAliasLatest, resellerAlias, resellerAliasLatest;
	vector<CAliasIndex> aliasVtxPos;
	CTransaction selleraliastx, buyeraliastx, arbiteraliastx, reselleraliastx;
	bool isExpired;
	CSyscoinAddress arbiterAddressPayment, buyerAddressPayment, sellerAddressPayment, resellerAddressPayment;
	CPubKey arbiterKey;
	if(GetTxAndVtxOfAlias(escrow.vchArbiterAlias, arbiterAliasLatest, arbiteraliastx, aliasVtxPos, isExpired, true))
	{
		arbiterAlias.nHeight = vtxPos.front().nHeight;
		arbiterAlias.GetAliasFromList(aliasVtxPos);
		arbiterKey = CPubKey(arbiterAlias.vchPubKey);
		arbiterAlias.GetAddress(&arbiterAddressPayment, escrow.nPaymentOption);

	}

	aliasVtxPos.clear();
	CPubKey buyerKey;
	if(GetTxAndVtxOfAlias(escrow.vchBuyerAlias, buyerAliasLatest, buyeraliastx, aliasVtxPos, isExpired, true))
	{
		buyerAlias.nHeight = vtxPos.front().nHeight;
		buyerAlias.GetAliasFromList(aliasVtxPos);
		buyerKey = CPubKey(buyerAlias.vchPubKey);
		buyerAlias.GetAddress(&buyerAddressPayment, escrow.nPaymentOption);
	}
	aliasVtxPos.clear();
	CPubKey sellerKey;
	if(GetTxAndVtxOfAlias(escrow.vchSellerAlias, sellerAliasLatest, selleraliastx, aliasVtxPos, isExpired, true))
	{
		sellerAlias.nHeight = vtxPos.front().nHeight;
		sellerAlias.GetAliasFromList(aliasVtxPos);
		sellerKey = CPubKey(sellerAlias.vchPubKey);
		sellerAlias.GetAddress(&sellerAddressPayment, escrow.nPaymentOption);
	}

	const CWalletTx *wtxAliasIn = NULL;
	CScript scriptPubKeyAlias;

	COffer theOffer, linkOffer;
	CTransaction txOffer;
	vector<COffer> offerVtxPos;
	if (!GetTxAndVtxOfOffer( escrow.vchOffer, theOffer, txOffer, offerVtxPos, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4526 - " + _("Could not find an offer with this identifier"));
	theOffer.nHeight = vtxPos.front().nAcceptHeight;
	theOffer.GetOfferFromList(offerVtxPos);
	if(!theOffer.vchLinkOffer.empty())
	{
		vector<COffer> offerLinkVtxPos;
		if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, txOffer, offerLinkVtxPos, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4527 - " + _("Could not find an offer with this identifier"));
		linkOffer.nHeight = vtxPos.front().nAcceptHeight;
		linkOffer.GetOfferFromList(offerLinkVtxPos);
		if(GetTxAndVtxOfAlias(theOffer.vchAlias, resellerAliasLatest, reselleraliastx, aliasVtxPos, isExpired, true))
		{
			resellerAlias.nHeight = vtxPos.front().nHeight;
			resellerAlias.GetAliasFromList(aliasVtxPos);
			resellerAlias.GetAddress(&resellerAddressPayment, escrow.nPaymentOption);
		}
	}
	CAmount nCommission;
	COfferLinkWhitelistEntry foundEntry;
	if(theOffer.vchLinkOffer.empty())
	{
		theOffer.linkWhitelist.GetLinkEntryByHash(buyerAlias.vchAlias, foundEntry);
		nCommission = 0;
	}
	else
	{
		linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, foundEntry);
		nCommission = theOffer.GetPrice() - linkOffer.GetPrice(foundEntry);
	}
	CAmount nExpectedCommissionAmount, nExpectedAmount, nEscrowFee, nEscrowTotal;
	int precision = 2;
	if(!vtxPos.front().rawTx.empty())
	{
		string paymentOptionStr = GetPaymentOptionsString(escrow.nPaymentOption);
		nExpectedCommissionAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nCommission, vtxPos.front().nAcceptHeight, precision)*escrow.nQty;
		nExpectedAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), theOffer.GetPrice(foundEntry), vtxPos.front().nAcceptHeight, precision)*escrow.nQty;
		nEscrowFee = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nEscrowFee, vtxPos.front().nAcceptHeight, precision);
		int nExtFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr),  vtxPos.front().nAcceptHeight, precision);
		nEscrowTotal =  nExpectedAmount + nEscrowFee + (nExtFeePerByte*400);
	}
	else
	{
		nExpectedCommissionAmount = nCommission*escrow.nQty;
		nExpectedAmount = theOffer.GetPrice(foundEntry)*escrow.nQty;
		float fEscrowFee = getEscrowFee(sellerAlias.vchAliasPeg, theOffer.sCurrencyCode, vtxPos.front().nAcceptHeight, precision);
		nEscrowFee = GetEscrowArbiterFee(nExpectedAmount, fEscrowFee);
		int nFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString("SYS"),  vtxPos.front().nAcceptHeight,precision);
		nEscrowTotal =  nExpectedAmount + nEscrowFee + (nFeePerByte*400);
	}
	vector<unsigned char> vchLinkAlias;
	CAliasIndex theAlias;
	// who is initiating release arbiter or buyer?
	if(role == "arbiter")
	{
		if(!IsSyscoinTxMine(arbiteraliastx, "alias"))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the arbiter alias to complete this transaction"));
		wtxAliasIn = pwalletMain->GetWalletTx(arbiteraliastx.GetHash());
		CScript scriptPubKeyOrig;
		scriptPubKeyOrig = GetScriptForDestination(arbiterKey.GetID());
		if(arbiterAlias.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyOrig = CScript(arbiterAlias.multiSigInfo.vchRedeemScript.begin(), arbiterAlias.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << arbiterAlias.vchAlias << arbiterAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyOrig;
		vchLinkAlias = arbiterAlias.vchAlias;
		theAlias = arbiterAlias;
	}
	else if(role == "buyer")
	{
		if(!IsSyscoinTxMine(buyeraliastx, "alias"))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the buyer alias to complete this transaction"));
		wtxAliasIn = pwalletMain->GetWalletTx(buyeraliastx.GetHash());
		CScript scriptPubKeyOrig;
		scriptPubKeyOrig = GetScriptForDestination(buyerKey.GetID());
		if(buyerAlias.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyOrig = CScript(buyerAlias.multiSigInfo.vchRedeemScript.begin(), buyerAlias.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias = CScript() << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << buyerAlias.vchAlias << buyerAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyOrig;
		vchLinkAlias = buyerAlias.vchAlias;
		theAlias = buyerAlias;
	}

    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, vtxPos.front().txHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4525 - " + _("Failed to find escrow transaction"));
	if (!vtxPos.front().rawTx.empty() && !DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4581 - " + _("Could not decode external payment transaction"));
	unsigned int nOutMultiSig = 0;
	// create a raw tx that sends escrow amount to seller and collateral to buyer
    // inputs buyer txHash
	UniValue arrayCreateParams(UniValue::VARR);
	UniValue createTxInputsArray(UniValue::VARR);
	UniValue createTxInputUniValue(UniValue::VOBJ);
	UniValue createAddressUniValue(UniValue::VOBJ);
	createTxInputUniValue.push_back(Pair("txid", fundingTx.GetHash().ToString()));
	createTxInputUniValue.push_back(Pair("vout", (int)nOutMultiSig));
	createTxInputsArray.push_back(createTxInputUniValue);
	if(role == "arbiter")
	{
		// if linked offer send commission to affiliate
		if(!theOffer.vchLinkOffer.empty())
		{
			createAddressUniValue.push_back(Pair(resellerAddressPayment.ToString(), ValueFromAmount(nExpectedCommissionAmount)));
			createAddressUniValue.push_back(Pair(sellerAddressPayment.ToString(), ValueFromAmount(nExpectedAmount-nExpectedCommissionAmount)));
		}
		else
			createAddressUniValue.push_back(Pair(sellerAddressPayment.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressUniValue.push_back(Pair(arbiterAddressPayment.ToString(), ValueFromAmount(nEscrowFee)));
	}
	else if(role == "buyer")
	{
		// if linked offer send commission to affiliate
		if(!theOffer.vchLinkOffer.empty())
		{
			createAddressUniValue.push_back(Pair(resellerAddressPayment.ToString(), ValueFromAmount(nExpectedCommissionAmount)));
			createAddressUniValue.push_back(Pair(sellerAddressPayment.ToString(), ValueFromAmount(nExpectedAmount-nExpectedCommissionAmount)));
		}
		else
			createAddressUniValue.push_back(Pair(sellerAddressPayment.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressUniValue.push_back(Pair(buyerAddressPayment.ToString(), ValueFromAmount(nEscrowFee)));
	}

	arrayCreateParams.push_back(createTxInputsArray);
	arrayCreateParams.push_back(createAddressUniValue);
	arrayCreateParams.push_back(NullUniValue);
	// if external blockchain then we dont set the alias payments scriptpubkey
	arrayCreateParams.push_back(vtxPos.front().rawTx.empty());
	UniValue resCreate;
	try
	{
		resCreate = tableRPC.execute("createrawtransaction", arrayCreateParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resCreate.isStr())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4530 - " + _("Could not create escrow transaction: Invalid response from createrawtransaction"));
	string createEscrowSpendingTx = resCreate.get_str();

    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, vtxPos.front().txHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4525 - " + _("Failed to find escrow transaction"));
	if (!vtxPos.front().rawTx.empty() && !DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4581 - " + _("Could not decode external payment transaction"));
	unsigned int nOutMultiSig = 0;
	// Buyer/Arbiter signs it
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
 	UniValue arraySignParams(UniValue::VARR);
 	UniValue arraySignInputs(UniValue::VARR);

 	UniValue signUniValue(UniValue::VOBJ);
 	signUniValue.push_back(Pair("txid", fundingTx.GetHash().ToString()));
 	signUniValue.push_back(Pair("vout", (int)nOutMultiSig));
 	signUniValue.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
 	signUniValue.push_back(Pair("redeemScript", HexStr(escrow.vchRedeemScript)));
  	arraySignParams.push_back(createEscrowSpendingTx);
 	arraySignInputs.push_back(signUniValue);
 	arraySignParams.push_back(arraySignInputs);
	UniValue resSign;
	try
	{
		resSign = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resSign.isObject())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4531 - " + _("Could not sign escrow transaction: Invalid response from signrawtransaction"));

	const UniValue& o = resSign.get_obj();
	string hex_str = "";

	const UniValue& hex_value = find_value(o, "hex");
	if (hex_value.isStr())
		hex_str = hex_value.get_str();


	escrow.ClearEscrow();
	escrow.op = OP_ESCROW_RELEASE;
	escrow.rawTx = ParseHex(hex_str);
	escrow.nHeight = chainActive.Tip()->nHeight;
	escrow.bPaymentAck = false;
	escrow.vchLinkAlias = vchLinkAlias;

	const vector<unsigned char> &data = escrow.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashEscrow = vchFromValue(hash.GetHex());

    CScript scriptPubKeyOrigSeller, scriptPubKeySeller, scriptPubKeyOrigArbiter, scriptPubKeyArbiter;
	scriptPubKeySeller= GetScriptForDestination(sellerKey.GetID());
	scriptPubKeyArbiter= GetScriptForDestination(arbiterKey.GetID());

    scriptPubKeyOrigSeller << CScript::EncodeOP_N(OP_ESCROW_RELEASE) << vchEscrow << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyOrigSeller += scriptPubKeySeller;

	scriptPubKeyOrigArbiter << CScript::EncodeOP_N(OP_ESCROW_RELEASE) << vchEscrow << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyOrigArbiter += scriptPubKeyArbiter;

	vector<CRecipient> vecSend;
	CRecipient recipientSeller;
	CreateRecipient(scriptPubKeyOrigSeller, recipientSeller);
	vecSend.push_back(recipientSeller);

	CRecipient recipientArbiter;
	CreateRecipient(scriptPubKeyOrigArbiter, recipientArbiter);
	vecSend.push_back(recipientArbiter);

	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneySyscoin(vecSend, recipientSeller.nAmount+recipientArbiter.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, theAlias.multiSigInfo.vchAliases.size() > 0);
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
	{
		res.push_back(wtx.GetHash().GetHex());
	}
	return res;
}
UniValue escrowacknowledge(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowacknowledge <escrow guid>\n"
                        "Acknowledge escrow payment as seller of offer. Deducts qty of offer and increases number of sold inventory.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);


	EnsureWalletIsUnlocked();
	
    // this is a syscoin transaction
    CWalletTx wtx;
    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
	vector<CEscrow> vtxPos;
    if (!GetTxAndVtxOfEscrow( vchEscrow,
		escrow, tx, vtxPos))
        throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4532 - " + _("Could not find a escrow with this key"));

	CAliasIndex sellerAlias, sellerAliasLatest, buyerAlias, buyerAliasLatest, arbiterAlias, arbiterAliasLatest, resellerAlias, resellerAliasLatest;
	vector<CAliasIndex> aliasVtxPos;
	CTransaction selleraliastx, buyeraliastx, arbiteraliastx, reselleraliastx;
	bool isExpired;
	CSyscoinAddress arbiterAddressPayment, buyerAddressPayment, sellerAddressPayment, resellerAddressPayment;
	CPubKey sellerKey, buyerKey, arbiterKey, resellerKey;
	if(GetTxAndVtxOfAlias(escrow.vchSellerAlias, sellerAliasLatest, selleraliastx, aliasVtxPos, isExpired, true))
	{
		sellerAlias.nHeight = vtxPos.front().nHeight;
		sellerAlias.GetAliasFromList(aliasVtxPos);
		sellerKey = CPubKey(sellerAlias.vchPubKey);
		sellerAlias.GetAddress(&sellerAddressPayment, escrow.nPaymentOption);
	}
	if(GetTxAndVtxOfAlias(escrow.vchBuyerAlias, buyerAliasLatest, buyeraliastx, aliasVtxPos, isExpired, true))
	{
		buyerAlias.nHeight = vtxPos.front().nHeight;
		buyerAlias.GetAliasFromList(aliasVtxPos);
		buyerKey = CPubKey(buyerAlias.vchPubKey);
		buyerAlias.GetAddress(&buyerAddressPayment, escrow.nPaymentOption);
	}
	if(GetTxAndVtxOfAlias(escrow.vchArbiterAlias, arbiterAliasLatest, arbiteraliastx, aliasVtxPos, isExpired, true))
	{
		arbiterAlias.nHeight = vtxPos.front().nHeight;
		arbiterAlias.GetAliasFromList(aliasVtxPos);
		arbiterKey = CPubKey(arbiterAlias.vchPubKey);
		arbiterAlias.GetAddress(&arbiterAddressPayment, escrow.nPaymentOption);
	}

	COffer theOffer, linkOffer;
	CTransaction txOffer;
	vector<COffer> offerVtxPos;
	if (!GetTxAndVtxOfOffer( escrow.vchOffer, theOffer, txOffer, offerVtxPos, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4534 - " + _("Could not find an offer with this identifier"));
	theOffer.nHeight = vtxPos.front().nAcceptHeight;
	theOffer.GetOfferFromList(offerVtxPos);
	if(!theOffer.vchLinkOffer.empty())
	{
		vector<COffer> offerLinkVtxPos;
		if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, txOffer, offerLinkVtxPos, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4535 - " + _("Could not find an offer with this identifier"));
		linkOffer.nHeight = vtxPos.front().nAcceptHeight;
		linkOffer.GetOfferFromList(offerLinkVtxPos);

		if(GetTxAndVtxOfAlias(theOffer.vchAlias, resellerAliasLatest, reselleraliastx, aliasVtxPos, isExpired, true))
		{
			resellerAlias.nHeight = vtxPos.front().nHeight;
			resellerAlias.GetAliasFromList(aliasVtxPos);
			resellerKey = CPubKey(resellerAlias.vchPubKey);
			resellerAlias.GetAddress(&resellerAddressPayment, escrow.nPaymentOption);
		}

	}
	
	if(!IsSyscoinTxMine(selleraliastx, "alias"))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the seller alias to complete this transaction"));
	const CWalletTx *wtxAliasIn = pwalletMain->GetWalletTx(selleraliastx.GetHash());
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig = GetScriptForDestination(sellerKey.GetID());
	if(sellerAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(sellerAlias.multiSigInfo.vchRedeemScript.begin(), sellerAlias.multiSigInfo.vchRedeemScript.end());
	CScript scriptPubKeyAlias = CScript() << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << sellerAlias.vchAlias << sellerAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;

	escrow.ClearEscrow();
	escrow.bPaymentAck = true;
	escrow.nHeight = chainActive.Tip()->nHeight;
	escrow.vchLinkAlias = sellerAlias.vchAlias;

	const vector<unsigned char> &data = escrow.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashEscrow = vchFromValue(hash.GetHex());

    CScript scriptPubKeyOrigBuyer, scriptPubKeyBuyer, scriptPubKeyOrigArbiter, scriptPubKeyArbiter;
	scriptPubKeyBuyer= GetScriptForDestination(buyerKey.GetID());

    scriptPubKeyOrigBuyer << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyOrigBuyer += scriptPubKeyBuyer;

	scriptPubKeyOrigArbiter << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyOrigArbiter += scriptPubKeyArbiter;

	vector<CRecipient> vecSend;
	CRecipient recipientBuyer;
	CreateRecipient(scriptPubKeyOrigBuyer, recipientBuyer);
	vecSend.push_back(recipientBuyer);

	CRecipient recipientArbiter;
	CreateRecipient(scriptPubKeyOrigArbiter, recipientArbiter);
	vecSend.push_back(recipientArbiter);

	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, sellerAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneySyscoin(vecSend, recipientBuyer.nAmount+recipientArbiter.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, sellerAlias.multiSigInfo.vchAliases.size() > 0);
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
	{
		res.push_back(wtx.GetHash().GetHex());
	}
	return res;

}
UniValue escrowclaimrelease(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowclaimrelease <escrow guid>\n"
                        "Claim escrow funds released from buyer or arbiter using escrowrelease.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);


	EnsureWalletIsUnlocked();
	UniValue ret(UniValue::VARR);
    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
	vector<CEscrow> vtxPos;
    if (!GetTxAndVtxOfEscrow( vchEscrow,
		escrow, tx, vtxPos))
        throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4532 - " + _("Could not find a escrow with this key"));

	CAliasIndex sellerAlias, sellerAliasLatest, buyerAlias, buyerAliasLatest, arbiterAlias, arbiterAliasLatest, resellerAlias, resellerAliasLatest;
	vector<CAliasIndex> aliasVtxPos;
	CTransaction selleraliastx, buyeraliastx, arbiteraliastx, reselleraliastx;
	bool isExpired;
	CSyscoinAddress arbiterAddressPayment, buyerAddressPayment, sellerAddressPayment, resellerAddressPayment;
	CPubKey sellerKey, buyerKey, arbiterKey, resellerKey;
	if(GetTxAndVtxOfAlias(escrow.vchSellerAlias, sellerAliasLatest, selleraliastx, aliasVtxPos, isExpired, true))
	{
		sellerAlias.nHeight = vtxPos.front().nHeight;
		sellerAlias.GetAliasFromList(aliasVtxPos);
		sellerKey = CPubKey(sellerAlias.vchPubKey);
		sellerAlias.GetAddress(&sellerAddressPayment, escrow.nPaymentOption);
	}
	if(GetTxAndVtxOfAlias(escrow.vchBuyerAlias, buyerAliasLatest, buyeraliastx, aliasVtxPos, isExpired, true))
	{
		buyerAlias.nHeight = vtxPos.front().nHeight;
		buyerAlias.GetAliasFromList(aliasVtxPos);
		buyerKey = CPubKey(buyerAlias.vchPubKey);
		buyerAlias.GetAddress(&buyerAddressPayment, escrow.nPaymentOption);
	}
	if(GetTxAndVtxOfAlias(escrow.vchArbiterAlias, arbiterAliasLatest, arbiteraliastx, aliasVtxPos, isExpired, true))
	{
		arbiterAlias.nHeight = vtxPos.front().nHeight;
		arbiterAlias.GetAliasFromList(aliasVtxPos);
		arbiterKey = CPubKey(arbiterAlias.vchPubKey);
		arbiterAlias.GetAddress(&arbiterAddressPayment, escrow.nPaymentOption);
	}
	COffer theOffer, linkOffer;
	CTransaction txOffer;
	vector<COffer> offerVtxPos;
	if (!GetTxAndVtxOfOffer( escrow.vchOffer, theOffer, txOffer, offerVtxPos, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4534 - " + _("Could not find an offer with this identifier"));
	theOffer.nHeight = vtxPos.front().nAcceptHeight;
	theOffer.GetOfferFromList(offerVtxPos);
	if(!theOffer.vchLinkOffer.empty())
	{
		vector<COffer> offerLinkVtxPos;
		if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, txOffer, offerLinkVtxPos, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4535 - " + _("Could not find an offer with this identifier"));
		linkOffer.nHeight = vtxPos.front().nAcceptHeight;
		linkOffer.GetOfferFromList(offerLinkVtxPos);

		if(GetTxAndVtxOfAlias(theOffer.vchAlias, resellerAliasLatest, reselleraliastx, aliasVtxPos, isExpired, true))
		{
			resellerAlias.nHeight = vtxPos.front().nHeight;
			resellerAlias.GetAliasFromList(aliasVtxPos);
			resellerKey = CPubKey(resellerAlias.vchPubKey);
			resellerAlias.GetAddress(&resellerAddressPayment, escrow.nPaymentOption);
		}
	}
	CAmount nCommission;
	COfferLinkWhitelistEntry foundEntry;
	if(theOffer.vchLinkOffer.empty())
	{
		theOffer.linkWhitelist.GetLinkEntryByHash(buyerAlias.vchAlias, foundEntry);
		nCommission = 0;
	}
	else
	{
		linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, foundEntry);
		nCommission = theOffer.GetPrice() - linkOffer.GetPrice(foundEntry);
	}
	int precision = 2;
	CAmount nExpectedCommissionAmount, nExpectedAmount, nEscrowFee, nEscrowTotal;
	if(!vtxPos.front().rawTx.empty())
	{
		string paymentOptionStr = GetPaymentOptionsString(escrow.nPaymentOption);
		nExpectedCommissionAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nCommission, vtxPos.front().nAcceptHeight, precision)*escrow.nQty;
		nExpectedAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), theOffer.GetPrice(foundEntry), vtxPos.front().nAcceptHeight, precision)*escrow.nQty;
		nEscrowFee = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nEscrowFee, vtxPos.front().nAcceptHeight, precision);
		int nExtFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr),  vtxPos.front().nAcceptHeight, precision);
		nEscrowTotal =  nExpectedAmount + nEscrowFee + (nExtFeePerByte*400);
	}
	else
	{
		nExpectedCommissionAmount = nCommission*escrow.nQty;
		nExpectedAmount = theOffer.GetPrice(foundEntry)*escrow.nQty;
		float fEscrowFee = getEscrowFee(sellerAlias.vchAliasPeg, theOffer.sCurrencyCode, vtxPos.front().nAcceptHeight, precision);
		nEscrowFee = GetEscrowArbiterFee(nExpectedAmount, fEscrowFee);
		int nFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString("SYS"),  vtxPos.front().nAcceptHeight,precision);
		nEscrowTotal =  nExpectedAmount + nEscrowFee + (nFeePerByte*400);
	}
	bool foundSellerPayment = false;
	bool foundCommissionPayment = false;
	bool foundFeePayment = false;
	UniValue arrayDecodeParams(UniValue::VARR);
	arrayDecodeParams.push_back(HexStr(escrow.rawTx));
	UniValue decodeRes;
	try
	{
		decodeRes = tableRPC.execute("decoderawtransaction", arrayDecodeParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!decodeRes.isObject())
	{
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4538 - " + _("Could not decode escrow transaction: Invalid response from decoderawtransaction"));
	}
	const UniValue& decodeo = decodeRes.get_obj();
	const UniValue& vout_value = find_value(decodeo, "vout");
	if (!vout_value.isArray())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4539 - " + _("Could not decode escrow transaction: Cannot find VOUT from transaction"));
	const UniValue &vouts = vout_value.get_array();
    for (unsigned int idx = 0; idx < vouts.size(); idx++) {
        const UniValue& vout = vouts[idx];
		const UniValue &voutObj = vout.get_obj();
		const UniValue &voutValue = find_value(voutObj, "value");
		if(!voutValue.isNum())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4540 - " + _("Could not decode escrow transaction: Invalid VOUT value"));
		int64_t iVout = AmountFromValue(voutValue);
		UniValue scriptPubKeyValue = find_value(voutObj, "scriptPubKey");
		if(!scriptPubKeyValue.isObject())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4541 - " + _("Could not decode escrow transaction: Invalid scriptPubKey value"));
		const UniValue &scriptPubKeyValueObj = scriptPubKeyValue.get_obj();

		const UniValue &typeValue = find_value(scriptPubKeyValueObj, "type");
		const UniValue &addressesValue = find_value(scriptPubKeyValueObj, "addresses");
		if(!typeValue.isStr())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4542 - " + _("Could not decode escrow transaction: Invalid type"));
		if(!addressesValue.isArray())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4543 - " + _("Could not decode escrow transaction: Invalid addresses"));

		const UniValue &addresses = addressesValue.get_array();
		const UniValue& address = addresses[0];
		if(!address.isStr())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4552 - " + _("Could not decode escrow transaction: Invalid address"));
		string strAddress = address.get_str();
		if(typeValue.get_str() == "multisig")
		{
			const UniValue &reqSigsValue = find_value(scriptPubKeyValueObj, "reqSigs");
			if(!reqSigsValue.isNum())
				throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4544 - " + _("Could not decode escrow transaction: Invalid number of signatures"));
			vector<CPubKey> pubKeys;
			for (unsigned int idx = 0; idx < addresses.size(); idx++) {
				const UniValue& address = addresses[idx];
				if(!address.isStr())
					throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4545 - " + _("Could not decode escrow transaction: Invalid address"));
				CSyscoinAddress aliasAddress = CSyscoinAddress(address.get_str());
				if(aliasAddress.vchPubKey.empty())
					throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4546 - " + _("Could not decode escrow transaction: One or more of the multisig addresses do not refer to an alias"));
				CPubKey pubkey(aliasAddress.vchPubKey);
				pubKeys.push_back(pubkey);
			}
			CScript script = GetScriptForMultisig(reqSigsValue.get_int(), pubKeys);
			CScriptID innerID(script);
			CSyscoinAddress aliasAddress(innerID, PaymentOptionToAddressType(escrow.nPaymentOption));
			strAddress = aliasAddress.ToString();
		}

		// check arb fee is paid to arbiter or buyer
		if(!foundFeePayment)
		{
			if(arbiterAddressPayment.ToString() == strAddress && iVout >= nEscrowFee)
				foundFeePayment = true;
		}
		if(!foundFeePayment)
		{
			if(buyerAddressPayment.ToString() == strAddress  && iVout >= nEscrowFee)
				foundFeePayment = true;
		}
		if(!theOffer.vchLinkOffer.empty())
		{
			if(!foundCommissionPayment)
			{
				if(resellerAddressPayment.ToString() == strAddress  && iVout >= nExpectedCommissionAmount)
				{
					foundCommissionPayment = true;
				}
			}
			if(!foundSellerPayment)
			{
				if(sellerAddressPayment.ToString() == strAddress  && iVout >= (nExpectedAmount-nExpectedCommissionAmount))
				{
					foundSellerPayment = true;
				}
			}
		}
		else if(!foundSellerPayment)
		{
			if(sellerAddressPayment.ToString() == strAddress && iVout >= nExpectedAmount)
			{
				foundSellerPayment = true;
			}
		}
	}
	if(!foundSellerPayment)
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4547 - " + _("Expected payment amount not found in escrow"));
	if(!foundFeePayment)
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4548 - " + _("Expected fee payment to arbiter or buyer not found in escrow"));
	if(!theOffer.vchLinkOffer.empty() && !foundCommissionPayment)
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4549 - " + _("Expected commission to affiliate not found in escrow"));
    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, vtxPos.front().txHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4525 - " + _("Failed to find escrow transaction"));
	if (!vtxPos.front().rawTx.empty() && !DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4581 - " + _("Could not decode external payment transaction"));
	unsigned int nOutMultiSig = 0;
    // Seller signs it
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
 	UniValue arraySignParams(UniValue::VARR);
 	UniValue arraySignInputs(UniValue::VARR);

 	UniValue signUniValue(UniValue::VOBJ);
 	signUniValue.push_back(Pair("txid", fundingTx.GetHash().ToString()));
 	signUniValue.push_back(Pair("vout", (int)nOutMultiSig));
 	signUniValue.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
 	signUniValue.push_back(Pair("redeemScript", HexStr(escrow.vchRedeemScript)));
  	arraySignParams.push_back(HexStr(escrow.rawTx));
 	arraySignInputs.push_back(signUniValue);
 	arraySignParams.push_back(arraySignInputs);
	UniValue resSign;
	try
	{
		resSign = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resSign.isObject())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4550 - " + _("Could not sign escrow transaction: Invalid response from signrawtransaction"));

	const UniValue& o = resSign.get_obj();
	string hex_str = "";

	const UniValue& hex_value = find_value(o, "hex");
	if (hex_value.isStr())
		hex_str = hex_value.get_str();

	CTransaction rawTx;
	DecodeHexTx(rawTx,hex_str);
	ret.push_back(hex_str);
	ret.push_back(rawTx.GetHash().GetHex());
	return ret;


}
UniValue escrowcompleterelease(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
		"escrowcompleterelease <escrow guid> <rawtx> \n"
                         "Completes an escrow release by creating the escrow complete release transaction on syscoin blockchain.\n"
						 "<rawtx> Raw syscoin escrow transaction. Enter the raw tx result from escrowclaimrelease.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
	string rawTx = params[1].get_str();
	CTransaction myRawTx;
	DecodeHexTx(myRawTx,rawTx);
    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
	vector<CEscrow> vtxPos;
    if (!GetTxAndVtxOfEscrow( vchEscrow,
		escrow, tx, vtxPos))
        throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4551 - " + _("Could not find a escrow with this key"));

	bool extPayment = false;
	if (!vtxPos.front().rawTx.empty())
		extPayment = true;

	CAliasIndex sellerAlias, sellerAliasLatest, buyerAlias, buyerAliasLatest, arbiterAlias, arbiterAliasLatest, resellerAlias, resellerAliasLatest;
	vector<CAliasIndex> aliasVtxPos;
	CTransaction selleraliastx, buyeraliastx, arbiteraliastx, reselleraliastx;
	bool isExpired;
	CPubKey arbiterKey;
	if(GetTxAndVtxOfAlias(escrow.vchArbiterAlias, arbiterAliasLatest, arbiteraliastx, aliasVtxPos, isExpired, true))
	{
		arbiterAlias.nHeight = vtxPos.front().nHeight;
		arbiterAlias.GetAliasFromList(aliasVtxPos);
		arbiterKey = CPubKey(arbiterAlias.vchPubKey);
	}

	aliasVtxPos.clear();
	CPubKey buyerKey;
	if(GetTxAndVtxOfAlias(escrow.vchBuyerAlias, buyerAliasLatest, buyeraliastx, aliasVtxPos, isExpired, true))
	{
		buyerAlias.nHeight = vtxPos.front().nHeight;
		buyerAlias.GetAliasFromList(aliasVtxPos);
		buyerKey = CPubKey(buyerAlias.vchPubKey);
	}
	aliasVtxPos.clear();
	CPubKey sellerKey;
	if(GetTxAndVtxOfAlias(escrow.vchSellerAlias, sellerAliasLatest, selleraliastx, aliasVtxPos, isExpired, true))
	{
		sellerAlias.nHeight = vtxPos.front().nHeight;
		sellerAlias.GetAliasFromList(aliasVtxPos);
		sellerKey = CPubKey(sellerAlias.vchPubKey);
	}


	const CWalletTx *wtxAliasIn = NULL;
	vector<unsigned char> vchLinkAlias;
	CScript scriptPubKeyAlias;
	if(!IsSyscoinTxMine(selleraliastx, "alias"))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the seller alias to complete this transaction"));
	wtxAliasIn = pwalletMain->GetWalletTx(selleraliastx.GetHash());
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig= GetScriptForDestination(sellerKey.GetID());
	if(sellerAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(sellerAlias.multiSigInfo.vchRedeemScript.begin(), sellerAlias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias = CScript() << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << sellerAlias.vchAlias << sellerAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;
	vchLinkAlias = sellerAlias.vchAlias;


	escrow.ClearEscrow();
	escrow.op = OP_ESCROW_COMPLETE;
	escrow.bPaymentAck = false;
	escrow.nHeight = chainActive.Tip()->nHeight;
	escrow.vchLinkAlias = vchLinkAlias;
	escrow.redeemTxId = myRawTx.GetHash();

    CScript scriptPubKeyBuyer, scriptPubKeySeller, scriptPubKeyArbiter;

	const vector<unsigned char> &data = escrow.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashEscrow = vchFromValue(hash.GetHex());
    scriptPubKeyBuyer << CScript::EncodeOP_N(OP_ESCROW_RELEASE) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyBuyer += GetScriptForDestination(buyerKey.GetID());
    scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_RELEASE) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeySeller += GetScriptForDestination(sellerKey.GetID());
    scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_RELEASE) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyArbiter += GetScriptForDestination(arbiterKey.GetID());
	vector<CRecipient> vecSend;
	CRecipient recipientBuyer, recipientSeller, recipientArbiter;
	CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
	vecSend.push_back(recipientBuyer);
	CreateRecipient(scriptPubKeySeller, recipientSeller);
	vecSend.push_back(recipientSeller);
	CreateRecipient(scriptPubKeyArbiter, recipientArbiter);
	vecSend.push_back(recipientArbiter);

	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, sellerAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneySyscoin(vecSend, recipientBuyer.nAmount+recipientSeller.nAmount+recipientArbiter.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, true);
	UniValue returnRes;
	UniValue sendParams(UniValue::VARR);
	sendParams.push_back(rawTx);
	try
	{
		// broadcast the payment transaction to syscoin network if not external transaction
		if (!extPayment)
			returnRes = tableRPC.execute("sendrawtransaction", sendParams);
	}
	catch (UniValue& objError)
	{
	}
	UniValue signParams(UniValue::VARR);
	signParams.push_back(EncodeHexTx(wtx));
	UniValue res(UniValue::VARR);
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
	if(!bComplete)
	{
		res.push_back(hex_str);
		res.push_back("false");
		return res;
	}
	res.push_back(wtx.GetHash().GetHex());
	return res;
}
UniValue escrowrefund(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
		"escrowrefund <escrow guid> <user role>\n"
                        "Refunds escrow funds back to buyer, buyer needs to sign the output transaction and send to the network. User role represents either 'seller' or 'arbiter'\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
	string role = params[1].get_str();
    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

     // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
	vector<CEscrow> vtxPos;
    if (!GetTxAndVtxOfEscrow( vchEscrow,
		escrow, tx, vtxPos))
        throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4556 - " + _("Could not find a escrow with this key"));

 
	CAliasIndex sellerAlias, sellerAliasLatest, buyerAlias, buyerAliasLatest, arbiterAlias, arbiterAliasLatest, resellerAlias, resellerAliasLatest;
	vector<CAliasIndex> aliasVtxPos;
	CTransaction selleraliastx, buyeraliastx, arbiteraliastx, reselleraliastx;
	bool isExpired;
	CSyscoinAddress arbiterAddressPayment, buyerAddressPayment, sellerAddressPayment, resellerAddressPayment;
	CPubKey arbiterKey;
	if(GetTxAndVtxOfAlias(escrow.vchArbiterAlias, arbiterAliasLatest, arbiteraliastx, aliasVtxPos, isExpired, true))
	{
		arbiterAlias.nHeight = vtxPos.front().nHeight;
		arbiterAlias.GetAliasFromList(aliasVtxPos);
		arbiterKey = CPubKey(arbiterAlias.vchPubKey);
		arbiterAlias.GetAddress(&arbiterAddressPayment, escrow.nPaymentOption);
	}

	aliasVtxPos.clear();
	CPubKey buyerKey;
	if(GetTxAndVtxOfAlias(escrow.vchBuyerAlias, buyerAliasLatest, buyeraliastx, aliasVtxPos, isExpired, true))
	{
		buyerAlias.nHeight = vtxPos.front().nHeight;
		buyerAlias.GetAliasFromList(aliasVtxPos);
		buyerKey = CPubKey(buyerAlias.vchPubKey);
		buyerAlias.GetAddress(&buyerAddressPayment, escrow.nPaymentOption);
	}
	aliasVtxPos.clear();
	CPubKey sellerKey;
	if(GetTxAndVtxOfAlias(escrow.vchSellerAlias, sellerAliasLatest, selleraliastx, aliasVtxPos, isExpired, true))
	{
		sellerAlias.nHeight = vtxPos.front().nHeight;
		sellerAlias.GetAliasFromList(aliasVtxPos);
		sellerKey = CPubKey(sellerAlias.vchPubKey);
		sellerAlias.GetAddress(&sellerAddressPayment, escrow.nPaymentOption);
	}

	COffer theOffer, linkOffer;
	CTransaction txOffer;
	vector<COffer> offerVtxPos;
	if (!GetTxAndVtxOfOffer( escrow.vchOffer, theOffer, txOffer, offerVtxPos, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4559 - " + _("Could not find an offer with this identifier"));
	theOffer.nHeight = vtxPos.front().nAcceptHeight;
	theOffer.GetOfferFromList(offerVtxPos);
	if(!theOffer.vchLinkOffer.empty())
	{
		vector<COffer> offerLinkVtxPos;
		if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, txOffer, offerLinkVtxPos, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4560 - " + _("Could not find an offer with this identifier"));
		linkOffer.nHeight = vtxPos.front().nAcceptHeight;
		linkOffer.GetOfferFromList(offerLinkVtxPos);

		linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, foundEntry);
	}
	CAmount nCommission;
	COfferLinkWhitelistEntry foundEntry;
	if(theOffer.vchLinkOffer.empty())
	{
		theOffer.linkWhitelist.GetLinkEntryByHash(buyerAlias.vchAlias, foundEntry);
		nCommission = 0;
	}
	else
	{
		linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, foundEntry);
		nCommission = theOffer.GetPrice() - linkOffer.GetPrice(foundEntry);
	}
	CAmount nExpectedCommissionAmount, nExpectedAmount, nEscrowFee, nEscrowTotal;
	int precision = 2;
	if(!vtxPos.front().rawTx.empty())
	{
		string paymentOptionStr = GetPaymentOptionsString(escrow.nPaymentOption);
		nExpectedCommissionAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nCommission, vtxPos.front().nAcceptHeight, precision)*escrow.nQty;
		nExpectedAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), theOffer.GetPrice(foundEntry), vtxPos.front().nAcceptHeight, precision)*escrow.nQty;
		nEscrowFee = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nEscrowFee, vtxPos.front().nAcceptHeight, precision);
		int nExtFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr),  vtxPos.front().nAcceptHeight, precision);
		nEscrowTotal =  nExpectedAmount + nEscrowFee + (nExtFeePerByte*400);
	}
	else
	{
		nExpectedCommissionAmount = nCommission*escrow.nQty;
		nExpectedAmount = theOffer.GetPrice(foundEntry)*escrow.nQty;
		float fEscrowFee = getEscrowFee(sellerAlias.vchAliasPeg, theOffer.sCurrencyCode, vtxPos.front().nAcceptHeight, precision);
		nEscrowFee = GetEscrowArbiterFee(nExpectedAmount, fEscrowFee);
		int nFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString("SYS"),  vtxPos.front().nAcceptHeight,precision);
		nEscrowTotal =  nExpectedAmount + nEscrowFee + (nFeePerByte*400);
	}
	const CWalletTx *wtxAliasIn = NULL;
	vector<unsigned char> vchLinkAlias;
	CAliasIndex theAlias;
	CScript scriptPubKeyAlias;
	// who is initiating release arbiter or seller?
	if(role == "arbiter")
	{
		if(!IsSyscoinTxMine(arbiteraliastx, "alias"))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the arbiter alias to complete this transaction"));
		wtxAliasIn = pwalletMain->GetWalletTx(arbiteraliastx.GetHash());
		CScript scriptPubKeyOrig;
		scriptPubKeyOrig = GetScriptForDestination(arbiterKey.GetID());
		if(arbiterAlias.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyOrig = CScript(arbiterAlias.multiSigInfo.vchRedeemScript.begin(), arbiterAlias.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << arbiterAlias.vchAlias << arbiterAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyOrig;
		vchLinkAlias = arbiterAlias.vchAlias;
		theAlias = arbiterAlias;
	}
	else if(role == "seller")
	{
		if(!IsSyscoinTxMine(selleraliastx, "alias"))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the seller alias to complete this transaction"));
		wtxAliasIn = pwalletMain->GetWalletTx(selleraliastx.GetHash());
		CScript scriptPubKeyOrig;
		scriptPubKeyOrig = GetScriptForDestination(sellerKey.GetID());
		if(sellerAlias.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyOrig = CScript(sellerAlias.multiSigInfo.vchRedeemScript.begin(), sellerAlias.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias = CScript() << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << sellerAlias.vchAlias << sellerAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyOrig;
		vchLinkAlias = sellerAlias.vchAlias;
		theAlias = sellerAlias;
	}
    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, vtxPos.front().txHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4525 - " + _("Failed to find escrow transaction"));
	if (!vtxPos.front().rawTx.empty() && !DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4581 - " + _("Could not decode external payment transaction"));
	unsigned int nOutMultiSig = 0;
	// refunds buyer from escrow
	UniValue arrayCreateParams(UniValue::VARR);
	UniValue createTxInputsArray(UniValue::VARR);
	UniValue createTxInputUniValue(UniValue::VOBJ);
	UniValue createAddressUniValue(UniValue::VOBJ);
	createTxInputUniValue.push_back(Pair("txid", fundingTx.GetHash().ToString()));
	createTxInputUniValue.push_back(Pair("vout", (int)nOutMultiSig));
	createTxInputsArray.push_back(createTxInputUniValue);
	if(role == "arbiter")
	{
		createAddressUniValue.push_back(Pair(buyerAddressPayment.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressUniValue.push_back(Pair(arbiterAddressPayment.ToString(), ValueFromAmount(nEscrowFee)));
	}
	else if(role == "seller")
	{
		createAddressUniValue.push_back(Pair(buyerAddressPayment.ToString(), ValueFromAmount(nExpectedAmount+nEscrowFee)));
	}
	arrayCreateParams.push_back(createTxInputsArray);
	arrayCreateParams.push_back(createAddressUniValue);
	arrayCreateParams.push_back(NullUniValue);
	// if external blockchain then we dont set the alias payments scriptpubkey
	arrayCreateParams.push_back(vtxPos.front().rawTx.empty());
	UniValue resCreate;
	try
	{
		resCreate = tableRPC.execute("createrawtransaction", arrayCreateParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resCreate.isStr())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4563 - " + _("Could not create escrow transaction: Invalid response from createrawtransaction"));
	string createEscrowSpendingTx = resCreate.get_str();
    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, vtxPos.front().txHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4525 - " + _("Failed to find escrow transaction"));
	if (!vtxPos.front().rawTx.empty() && !DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4581 - " + _("Could not decode external payment transaction"));
	unsigned int nOutMultiSig = 0;
	// Buyer/Arbiter signs it
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
 	UniValue arraySignParams(UniValue::VARR);
 	UniValue arraySignInputs(UniValue::VARR);

 	UniValue signUniValue(UniValue::VOBJ);
 	signUniValue.push_back(Pair("txid", fundingTx.GetHash().ToString()));
 	signUniValue.push_back(Pair("vout", (int)nOutMultiSig));
 	signUniValue.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
 	signUniValue.push_back(Pair("redeemScript", HexStr(escrow.vchRedeemScript)));
  	arraySignParams.push_back(createEscrowSpendingTx);
 	arraySignInputs.push_back(signUniValue);
 	arraySignParams.push_back(arraySignInputs);

	UniValue resSign;
	try
	{
		resSign = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resSign.isObject())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4564 - " + _("Could not sign escrow transaction: Invalid response from signrawtransaction"));

	const UniValue& o = resSign.get_obj();
	string hex_str = "";

	const UniValue& hex_value = find_value(o, "hex");
	if (hex_value.isStr())
		hex_str = hex_value.get_str();

	escrow.ClearEscrow();
	escrow.op = OP_ESCROW_REFUND;
	escrow.bPaymentAck = false;
	escrow.rawTx = ParseHex(hex_str);
	escrow.nHeight = chainActive.Tip()->nHeight;
	escrow.vchLinkAlias = vchLinkAlias;

	const vector<unsigned char> &data = escrow.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashEscrow = vchFromValue(hash.GetHex());

    CScript scriptPubKeyOrigBuyer, scriptPubKeyBuyer, scriptPubKeyOrigArbiter, scriptPubKeyArbiter;
	scriptPubKeyBuyer= GetScriptForDestination(buyerKey.GetID());
	scriptPubKeyArbiter= GetScriptForDestination(arbiterKey.GetID());

    scriptPubKeyOrigBuyer << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyOrigBuyer += scriptPubKeyBuyer;

	scriptPubKeyOrigArbiter << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << vchFromString("0") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyOrigArbiter += scriptPubKeyArbiter;

	vector<CRecipient> vecSend;
	CRecipient recipientBuyer;
	CreateRecipient(scriptPubKeyOrigBuyer, recipientBuyer);
	vecSend.push_back(recipientBuyer);

	CRecipient recipientArbiter;
	CreateRecipient(scriptPubKeyOrigArbiter, recipientArbiter);
	vecSend.push_back(recipientArbiter);

	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneySyscoin(vecSend, recipientBuyer.nAmount+recipientArbiter.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, theAlias.multiSigInfo.vchAliases.size() > 0);
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
	{
		res.push_back(wtx.GetHash().GetHex());
	}
	return res;
}
UniValue escrowclaimrefund(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowclaimrefund <escrow guid>\n"
                        "Claim escrow funds released from seller or arbiter using escrowrefund.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);


	EnsureWalletIsUnlocked();
    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
	vector<CEscrow> vtxPos;
    if (!GetTxAndVtxOfEscrow( vchEscrow,
		escrow, tx, vtxPos))
        throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4565 - " + _("Could not find a escrow with this key"));

	CAliasIndex sellerAlias, sellerAliasLatest, buyerAlias, buyerAliasLatest, arbiterAlias, arbiterAliasLatest, resellerAlias, resellerAliasLatest;
	vector<CAliasIndex> aliasVtxPos;
	CTransaction selleraliastx, buyeraliastx, arbiteraliastx, reselleraliastx;
	bool isExpired;
	CSyscoinAddress buyerAddressPayment;
	CPubKey arbiterKey;
	if(GetTxAndVtxOfAlias(escrow.vchArbiterAlias, arbiterAliasLatest, arbiteraliastx, aliasVtxPos, isExpired, true))
	{
		arbiterAlias.nHeight = vtxPos.front().nHeight;
		arbiterAlias.GetAliasFromList(aliasVtxPos);
		arbiterKey = CPubKey(arbiterAlias.vchPubKey);
	}

	aliasVtxPos.clear();
	CPubKey buyerKey;
	if(GetTxAndVtxOfAlias(escrow.vchBuyerAlias, buyerAliasLatest, buyeraliastx, aliasVtxPos, isExpired, true))
	{
		buyerAlias.nHeight = vtxPos.front().nHeight;
		buyerAlias.GetAliasFromList(aliasVtxPos);
		buyerKey = CPubKey(buyerAlias.vchPubKey);
		buyerAlias.GetAddress(&buyerAddressPayment, escrow.nPaymentOption);
	}
	aliasVtxPos.clear();
	CPubKey sellerKey;
	if(GetTxAndVtxOfAlias(escrow.vchSellerAlias, sellerAliasLatest, selleraliastx, aliasVtxPos, isExpired, true))
	{
		sellerAlias.nHeight = vtxPos.front().nHeight;
		sellerAlias.GetAliasFromList(aliasVtxPos);
		sellerKey = CPubKey(sellerAlias.vchPubKey);
	}

 
	COffer theOffer, linkOffer;
	CTransaction txOffer;
	vector<COffer> offerVtxPos;
	if (!GetTxAndVtxOfOffer( escrow.vchOffer, theOffer, txOffer, offerVtxPos, true))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4568 - " + _("Could not find an offer with this identifier"));
	theOffer.nHeight = vtxPos.front().nAcceptHeight;
	theOffer.GetOfferFromList(offerVtxPos);
	if(!theOffer.vchLinkOffer.empty())
	{
		vector<COffer> offerLinkVtxPos;
		if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, txOffer, offerLinkVtxPos, true))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4569 - " + _("Could not find an offer with this identifier"));
		linkOffer.nHeight = vtxPos.front().nAcceptHeight;
		linkOffer.GetOfferFromList(offerLinkVtxPos);
	}

	CAmount nCommission;
	COfferLinkWhitelistEntry foundEntry;
	if(theOffer.vchLinkOffer.empty())
	{
		theOffer.linkWhitelist.GetLinkEntryByHash(buyerAlias.vchAlias, foundEntry);
		nCommission = 0;
	}
	else
	{
		linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchAlias, foundEntry);
		nCommission = theOffer.GetPrice() - linkOffer.GetPrice(foundEntry);
	}
	CAmount nExpectedCommissionAmount, nExpectedAmount, nEscrowFee, nEscrowTotal;
	int precision = 2;
	if(!vtxPos.front().rawTx.empty())
	{
		string paymentOptionStr = GetPaymentOptionsString(escrow.nPaymentOption);
		nExpectedCommissionAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nCommission, vtxPos.front().nAcceptHeight, precision)*escrow.nQty;
		nExpectedAmount = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), theOffer.GetPrice(foundEntry), vtxPos.front().nAcceptHeight, precision)*escrow.nQty;
		nEscrowFee = convertSyscoinToCurrencyCode(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr), nEscrowFee, vtxPos.front().nAcceptHeight, precision);
		int nExtFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString(paymentOptionStr),  vtxPos.front().nAcceptHeight, precision);
		nEscrowTotal =  nExpectedAmount + nEscrowFee + (nExtFeePerByte*400);
	}
	else
	{
		nExpectedCommissionAmount = nCommission*escrow.nQty;
		nExpectedAmount = theOffer.GetPrice(foundEntry)*escrow.nQty;
		float fEscrowFee = getEscrowFee(sellerAlias.vchAliasPeg, theOffer.sCurrencyCode, vtxPos.front().nAcceptHeight, precision);
		nEscrowFee = GetEscrowArbiterFee(nExpectedAmount, fEscrowFee);
		int nFeePerByte = getFeePerByte(sellerAlias.vchAliasPeg, vchFromString("SYS"),  vtxPos.front().nAcceptHeight,precision);
		nEscrowTotal =  nExpectedAmount + nEscrowFee + (nFeePerByte*400);
	}

	// decode rawTx and check it pays enough and it pays to buyer appropriately
	// check that right amount is going to be sent to buyer
	UniValue arrayDecodeParams(UniValue::VARR);

	arrayDecodeParams.push_back(HexStr(escrow.rawTx));
	UniValue decodeRes;
	try
	{
		decodeRes = tableRPC.execute("decoderawtransaction", arrayDecodeParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!decodeRes.isObject())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4571 - " + _("Could not decode escrow transaction: Invalid response from decoderawtransaction"));
	bool foundRefundPayment = false;
	const UniValue& decodeo = decodeRes.get_obj();
	const UniValue& vout_value = find_value(decodeo, "vout");
	if (!vout_value.isArray())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4572 - " + _("Could not decode escrow transaction: Cannot find VOUT from transaction"));
	const UniValue &vouts = vout_value.get_array();
    for (unsigned int idx = 0; idx < vouts.size(); idx++) {
        const UniValue& vout = vouts[idx];
		const UniValue &voutObj = vout.get_obj();
		const UniValue &voutValue = find_value(voutObj, "value");
		if(!voutValue.isNum())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4573 - " + _("Could not decode escrow transaction: Invalid VOUT value"));
		int64_t iVout = AmountFromValue(voutValue);
		UniValue scriptPubKeyValue = find_value(voutObj, "scriptPubKey");
		if(!scriptPubKeyValue.isObject())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4574 - " + _("Could not decode escrow transaction: Invalid scriptPubKey value"));
		const UniValue &scriptPubKeyValueObj = scriptPubKeyValue.get_obj();
		const UniValue &typeValue = find_value(scriptPubKeyValueObj, "type");
		const UniValue &addressesValue = find_value(scriptPubKeyValueObj, "addresses");
		if(!typeValue.isStr())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4575 - " + _("Could not decode escrow transaction: Invalid type"));
		if(!addressesValue.isArray())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4576 - " + _("Could not decode escrow transaction: Invalid addresses"));

		const UniValue &addresses = addressesValue.get_array();
		const UniValue& address = addresses[0];
		if(!address.isStr())
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4577 - " + _("Could not decode escrow transaction: Invalid address"));
		string strAddress = address.get_str();
		if(typeValue.get_str() == "multisig")
		{
			const UniValue &reqSigsValue = find_value(scriptPubKeyValueObj, "reqSigs");
			if(!reqSigsValue.isNum())
				throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4578 - " + _("Could not decode escrow transaction: Invalid number of signatures"));
			vector<CPubKey> pubKeys;
			for (unsigned int idx = 0; idx < addresses.size(); idx++) {
				const UniValue& address = addresses[idx];
				if(!address.isStr())
					throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4579 - " + _("Could not decode escrow transaction: Invalid address"));
				CSyscoinAddress aliasAddress = CSyscoinAddress(address.get_str());
				if(aliasAddress.vchPubKey.empty())
					throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4580 - " + _("Could not decode escrow transaction: One or more of the multisig addresses do not refer to an alias"));
				CPubKey pubkey(aliasAddress.vchPubKey);
				pubKeys.push_back(pubkey);
			}
			CScript script = GetScriptForMultisig(reqSigsValue.get_int(), pubKeys);
			CScriptID innerID(script);
			CSyscoinAddress aliasAddress(innerID, PaymentOptionToAddressType(escrow.nPaymentOption));
			strAddress = aliasAddress.ToString();
		}
		if(!foundRefundPayment)
		{
			if(buyerAddressPayment.ToString() == strAddress && iVout >= nExpectedAmount)
				foundRefundPayment = true;
		}

	}
	if(!foundRefundPayment)
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4581 - " + _("Expected refund amount not found"));
    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, vtxPos.front().txHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4525 - " + _("Failed to find escrow transaction"));
	if (!vtxPos.front().rawTx.empty() && !DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4581 - " + _("Could not decode external payment transaction"));
	unsigned int nOutMultiSig = 0;
    // Buyer signs it
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
 	UniValue arraySignParams(UniValue::VARR);
 	UniValue arraySignInputs(UniValue::VARR);

 	UniValue signUniValue(UniValue::VOBJ);
 	signUniValue.push_back(Pair("txid", fundingTx.GetHash().ToString()));
 	signUniValue.push_back(Pair("vout", (int)nOutMultiSig));
 	signUniValue.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
 	signUniValue.push_back(Pair("redeemScript", HexStr(escrow.vchRedeemScript)));
  	arraySignParams.push_back(HexStr(escrow.rawTx));
 	arraySignInputs.push_back(signUniValue);
 	arraySignParams.push_back(arraySignInputs);
	UniValue resSign;
	try
	{
		resSign = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resSign.isObject())
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4582 - " + _("Could not sign escrow transaction: Invalid response from signrawtransaction"));

	const UniValue& o = resSign.get_obj();
	string hex_str = "";

	const UniValue& hex_value = find_value(o, "hex");
	if (hex_value.isStr())
		hex_str = hex_value.get_str();
	CTransaction rawTx;
	DecodeHexTx(rawTx,hex_str);
	UniValue ret(UniValue::VARR);
	ret.push_back(hex_str);
	ret.push_back(rawTx.GetHash().GetHex());
	return ret;
}
UniValue escrowcompleterefund(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
		"escrowcompleterefund <escrow guid> <rawtx> \n"
                         "Completes an escrow refund by creating the escrow complete refund transaction on syscoin blockchain.\n"
						 "<rawtx> Raw syscoin escrow transaction. Enter the raw tx result from escrowclaimrefund.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
	string rawTx = params[1].get_str();
	CTransaction myRawTx;
	DecodeHexTx(myRawTx,rawTx);
    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
	vector<CEscrow> vtxPos;
    if (!GetTxAndVtxOfEscrow( vchEscrow,
		escrow, tx, vtxPos))
        throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4583 - " + _("Could not find a escrow with this key"));

	bool extPayment = false;
	if (!vtxPos.front().rawTx.empty())
		extPayment = true;

	CAliasIndex sellerAlias, sellerAliasLatest, buyerAlias, buyerAliasLatest, arbiterAlias, arbiterAliasLatest, resellerAlias, resellerAliasLatest;
	vector<CAliasIndex> aliasVtxPos;
	CTransaction selleraliastx, buyeraliastx, arbiteraliastx, reselleraliastx;
	bool isExpired;
	CPubKey arbiterKey;
	if(GetTxAndVtxOfAlias(escrow.vchArbiterAlias, arbiterAliasLatest, arbiteraliastx, aliasVtxPos, isExpired, true))
	{
		arbiterAlias.nHeight = vtxPos.front().nHeight;
		arbiterAlias.GetAliasFromList(aliasVtxPos);
		arbiterKey = CPubKey(arbiterAlias.vchPubKey);
	}

	aliasVtxPos.clear();
	CPubKey buyerKey;
	if(GetTxAndVtxOfAlias(escrow.vchBuyerAlias, buyerAliasLatest, buyeraliastx, aliasVtxPos, isExpired, true))
	{
		buyerAlias.nHeight = vtxPos.front().nHeight;
		buyerAlias.GetAliasFromList(aliasVtxPos);
		buyerKey = CPubKey(buyerAlias.vchPubKey);
	}
	aliasVtxPos.clear();
	CPubKey sellerKey;
	if(GetTxAndVtxOfAlias(escrow.vchSellerAlias, sellerAliasLatest, selleraliastx, aliasVtxPos, isExpired, true))
	{
		sellerAlias.nHeight = vtxPos.front().nHeight;
		sellerAlias.GetAliasFromList(aliasVtxPos);
	}


	string strPrivateKey ;
	const CWalletTx *wtxAliasIn = NULL;
	vector<unsigned char> vchLinkAlias;
	CScript scriptPubKeyAlias;
	if(!IsSyscoinTxMine(buyeraliastx, "alias"))
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the buyer alias to complete this transaction"));
	wtxAliasIn = pwalletMain->GetWalletTx(buyeraliastx.GetHash());
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig= GetScriptForDestination(buyerKey.GetID());
	if(buyerAlias.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyOrig = CScript(buyerAlias.multiSigInfo.vchRedeemScript.begin(), buyerAlias.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias = CScript() << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << buyerAlias.vchAlias << buyerAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;
	vchLinkAlias = buyerAlias.vchAlias;


	escrow.ClearEscrow();
	escrow.op = OP_ESCROW_COMPLETE;
	escrow.bPaymentAck = false;
	escrow.nHeight = chainActive.Tip()->nHeight;
	escrow.vchLinkAlias = vchLinkAlias;
	escrow.redeemTxId = myRawTx.GetHash();

    CScript scriptPubKeyBuyer, scriptPubKeySeller, scriptPubKeyArbiter;

	const vector<unsigned char> &data = escrow.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashEscrow = vchFromValue(hash.GetHex());
    scriptPubKeyBuyer << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyBuyer += GetScriptForDestination(buyerKey.GetID());
    scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeySeller += GetScriptForDestination(sellerKey.GetID());
    scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
    scriptPubKeyArbiter += GetScriptForDestination(arbiterKey.GetID());
	vector<CRecipient> vecSend;
	CRecipient recipientBuyer, recipientSeller, recipientArbiter;
	CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
	vecSend.push_back(recipientBuyer);
	CreateRecipient(scriptPubKeySeller, recipientSeller);
	vecSend.push_back(recipientSeller);
	CreateRecipient(scriptPubKeyArbiter, recipientArbiter);
	vecSend.push_back(recipientArbiter);

	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, buyerAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneySyscoin(vecSend, recipientBuyer.nAmount+recipientSeller.nAmount+recipientArbiter.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, true);
	UniValue returnRes;
	UniValue sendParams(UniValue::VARR);
	sendParams.push_back(rawTx);
	try
	{
		// broadcast the payment transaction to syscoin network if not external transaction
		if (!extPayment)
			returnRes = tableRPC.execute("sendrawtransaction", sendParams);
	}
	catch (UniValue& objError)
	{
	}
	UniValue signParams(UniValue::VARR);
	signParams.push_back(EncodeHexTx(wtx));
	UniValue res(UniValue::VARR);
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
	if(!bComplete)
	{
		res.push_back(hex_str);
		res.push_back("false");
		return res;
	}
	res.push_back(wtx.GetHash().GetHex());
	return res;
}
UniValue escrowfeedback(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 6)
        throw runtime_error(
		"escrowfeedback <escrow guid> <user role> <feedbackprimary> <ratingprimary> <feedbacksecondary> <ratingasecondary>\n"
                        "Send feedback for primary and secondary users in escrow, depending on who you are. Ratings are numbers from 1 to 5. User Role is either 'buyer', 'seller', or 'arbiter'.\n"
						"If you are the buyer, feedbackprimary is for seller and feedbacksecondary is for arbiter.\n"
						"If you are the seller, feedbackprimary is for buyer and feedbacksecondary is for arbiter.\n"
						"If you are the arbiter, feedbackprimary is for buyer and feedbacksecondary is for seller.\n"
						"If arbiter didn't do any work for this escrow you can leave his feedback empty and rating as a 0.\n"
                        + HelpRequiringPassphrase());
   // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
	string role = params[1].get_str();
	int nRatingPrimary = 0;
	int nRatingSecondary = 0;
	vector<unsigned char> vchFeedbackPrimary;
	vector<unsigned char> vchFeedbackSecondary;
	vchFeedbackPrimary = vchFromValue(params[2]);
	nRatingPrimary = boost::lexical_cast<int>(params[3].get_str());
	vchFeedbackSecondary = vchFromValue(params[4]);
	nRatingSecondary = boost::lexical_cast<int>(params[5].get_str());
    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow( vchEscrow,
		escrow, tx))
        throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4588 - " + _("Could not find a escrow with this key"));

	CAliasIndex arbiterAliasLatest, buyerAliasLatest, sellerAliasLatest;
	CTransaction arbiteraliastx, selleraliastx, buyeraliastx;
	GetTxOfAlias(escrow.vchArbiterAlias, arbiterAliasLatest, arbiteraliastx, true);
	CPubKey arbiterKey(arbiterAliasLatest.vchPubKey);

	GetTxOfAlias(escrow.vchBuyerAlias, buyerAliasLatest, buyeraliastx, true);
	CPubKey buyerKey(buyerAliasLatest.vchPubKey);

	GetTxOfAlias(escrow.vchSellerAlias, sellerAliasLatest, selleraliastx, true);
	CPubKey sellerKey(sellerAliasLatest.vchPubKey);
	vector <unsigned char> vchLinkAlias;
	CAliasIndex theAlias;
	CScript scriptPubKeyAlias;
	const CWalletTx *wtxAliasIn = NULL;
	if(role == "buyer")
	{
		if(!IsSyscoinTxMine(buyeraliastx, "alias"))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the buyer alias to complete this transaction"));
		wtxAliasIn = pwalletMain->GetWalletTx(buyeraliastx.GetHash());
		CScript scriptPubKeyAliasOrig= GetScriptForDestination(buyerKey.GetID());
		if(buyerAliasLatest.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyAliasOrig = CScript(buyerAliasLatest.multiSigInfo.vchRedeemScript.begin(), buyerAliasLatest.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias = CScript() << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << buyerAliasLatest.vchAlias << buyerAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyAliasOrig;
		vchLinkAlias = buyerAliasLatest.vchAlias;
		theAlias = buyerAliasLatest;
	}
	else if(role == "seller")
	{
		if(!IsSyscoinTxMine(selleraliastx, "alias"))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the seller alias to complete this transaction"));
		wtxAliasIn = pwalletMain->GetWalletTx(selleraliastx.GetHash());
		CScript scriptPubKeyAliasOrig = GetScriptForDestination(sellerKey.GetID());
		if(sellerAliasLatest.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyAliasOrig = CScript(sellerAliasLatest.multiSigInfo.vchRedeemScript.begin(), sellerAliasLatest.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias = CScript() << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << sellerAliasLatest.vchAlias << sellerAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyAliasOrig;
		vchLinkAlias = sellerAliasLatest.vchAlias;
		theAlias = sellerAliasLatest;
	}
	else if(role == "arbiter")
	{
		if(!IsSyscoinTxMine(arbiteraliastx, "alias"))
			throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4587 - " + _("You must own the arbiter alias to complete this transaction"));
		wtxAliasIn = pwalletMain->GetWalletTx(arbiteraliastx.GetHash());
		CScript scriptPubKeyAliasOrig = GetScriptForDestination(arbiterKey.GetID());
		if(arbiterAliasLatest.multiSigInfo.vchAliases.size() > 0)
			scriptPubKeyAliasOrig = CScript(arbiterAliasLatest.multiSigInfo.vchRedeemScript.begin(), arbiterAliasLatest.multiSigInfo.vchRedeemScript.end());
		scriptPubKeyAlias  = CScript() << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << arbiterAliasLatest.vchAlias << arbiterAliasLatest.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyAlias += scriptPubKeyAliasOrig;
		vchLinkAlias = arbiterAliasLatest.vchAlias;
		theAlias = arbiterAliasLatest;
	}

	escrow.ClearEscrow();
	escrow.op = OP_ESCROW_COMPLETE;
	escrow.bPaymentAck = false;
	escrow.nHeight = chainActive.Tip()->nHeight;
	escrow.vchLinkAlias = vchLinkAlias;
	// buyer
	if(role == "buyer")
	{
		CFeedback sellerFeedback(FEEDBACKBUYER, FEEDBACKSELLER);
		sellerFeedback.vchFeedback = vchFeedbackPrimary;
		sellerFeedback.nRating = nRatingPrimary;
		sellerFeedback.nHeight = chainActive.Tip()->nHeight;
		CFeedback arbiterFeedback(FEEDBACKBUYER, FEEDBACKARBITER);
		arbiterFeedback.vchFeedback = vchFeedbackSecondary;
		arbiterFeedback.nRating = nRatingSecondary;
		arbiterFeedback.nHeight = chainActive.Tip()->nHeight;
		escrow.feedback.push_back(arbiterFeedback);
		escrow.feedback.push_back(sellerFeedback);
	}
	// seller
	else if(role == "seller")
	{
		CFeedback buyerFeedback(FEEDBACKSELLER, FEEDBACKBUYER);
		buyerFeedback.vchFeedback = vchFeedbackPrimary;
		buyerFeedback.nRating = nRatingPrimary;
		buyerFeedback.nHeight = chainActive.Tip()->nHeight;
		CFeedback arbiterFeedback(FEEDBACKSELLER, FEEDBACKARBITER);
		arbiterFeedback.vchFeedback = vchFeedbackSecondary;
		arbiterFeedback.nRating = nRatingSecondary;
		arbiterFeedback.nHeight = chainActive.Tip()->nHeight;
		escrow.feedback.push_back(buyerFeedback);
		escrow.feedback.push_back(arbiterFeedback);
	}
	// arbiter
	else if(role == "arbiter")
	{
		CFeedback buyerFeedback(FEEDBACKARBITER, FEEDBACKBUYER);
		buyerFeedback.vchFeedback = vchFeedbackPrimary;
		buyerFeedback.nRating = nRatingPrimary;
		buyerFeedback.nHeight = chainActive.Tip()->nHeight;
		CFeedback sellerFeedback(FEEDBACKARBITER, FEEDBACKSELLER);
		sellerFeedback.vchFeedback = vchFeedbackSecondary;
		sellerFeedback.nRating = nRatingSecondary;
		sellerFeedback.nHeight = chainActive.Tip()->nHeight;
		escrow.feedback.push_back(buyerFeedback);
		escrow.feedback.push_back(sellerFeedback);
	}
	else
	{
		throw runtime_error("SYSCOIN_ESCROW_RPC_ERROR: ERRCODE: 4589 - " + _("You must be either the arbiter, buyer or seller to leave feedback on this escrow"));
	}
	const vector<unsigned char> &data = escrow.Serialize();
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashEscrow = vchFromValue(hash.GetHex());
	CScript scriptPubKeyBuyer, scriptPubKeySeller,scriptPubKeyArbiter, scriptPubKeyBuyerDestination, scriptPubKeySellerDestination, scriptPubKeyArbiterDestination;
	scriptPubKeyBuyerDestination= GetScriptForDestination(buyerKey.GetID());
	scriptPubKeySellerDestination= GetScriptForDestination(sellerKey.GetID());
	scriptPubKeyArbiterDestination= GetScriptForDestination(arbiterKey.GetID());
	vector<CRecipient> vecSend;
	CRecipient recipientBuyer, recipientSeller, recipientArbiter;
	scriptPubKeyBuyer << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
	scriptPubKeyBuyer += scriptPubKeyBuyerDestination;
	scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
	scriptPubKeyArbiter += scriptPubKeyArbiterDestination;
	scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << vchHashEscrow << OP_2DROP << OP_2DROP;
	scriptPubKeySeller += scriptPubKeySellerDestination;
	CreateRecipient(scriptPubKeySeller, recipientSeller);
	CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
	CreateRecipient(scriptPubKeyArbiter, recipientArbiter);
	// buyer
	if(role == "buyer")
	{
		vecSend.push_back(recipientSeller);
		vecSend.push_back(recipientArbiter);
	}
	// seller
	else if(role == "seller")
	{
		vecSend.push_back(recipientBuyer);
		vecSend.push_back(recipientArbiter);
	}
	// arbiter
	else if(role == "arbiter")
	{
		vecSend.push_back(recipientBuyer);
		vecSend.push_back(recipientSeller);
	}
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	vecSend.push_back(aliasRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneySyscoin(vecSend, recipientBuyer.nAmount+recipientSeller.nAmount+recipientArbiter.nAmount+fee.nAmount+aliasRecipient.nAmount, false, wtx, wtxAliasIn, theAlias.multiSigInfo.vchAliases.size() > 0);
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
	{
		res.push_back(wtx.GetHash().GetHex());
	}
	return res;
}
UniValue escrowinfo(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("escrowinfo <guid>\n"
                "Show stored values of a single escrow and its .\n");

    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

    // look for a transaction with this key, also returns
    // an escrow UniValue if it is found
    CTransaction tx;

	vector<CEscrow> vtxPos;

    UniValue oEscrow(UniValue::VOBJ);
    vector<unsigned char> vchValue;

	if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
		  throw runtime_error("failed to read from escrow DB");
	CEscrow ca = vtxPos.back();
	if (!GetSyscoinTransaction(ca.nHeight, ca.txHash, tx, Params().GetConsensus()))
		 throw runtime_error("failed to read escrow transaction");
    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvch) )
        throw runtime_error("could not decode escrow transcation");
	CTransaction offertx;
	COffer offer;
	vector<COffer> offerVtxPos;
	GetTxAndVtxOfOffer(ca.vchOffer, offer, offertx, offerVtxPos, true);
	offer.nHeight = vtxPos.front().nAcceptHeight;
	offer.GetOfferFromList(offerVtxPos);
    string sHeight = strprintf("%llu", ca.nHeight);
    oEscrow.push_back(Pair("escrow", stringFromVch(vchEscrow)));
	string sTime;
	CBlockIndex *pindex = chainActive[ca.nHeight];
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	int avgBuyerRating, avgSellerRating, avgArbiterRating;
	vector<CFeedback> buyerFeedBacks, sellerFeedBacks, arbiterFeedBacks;
	GetFeedback(buyerFeedBacks, avgBuyerRating, FEEDBACKBUYER, ca.feedback);
	GetFeedback(sellerFeedBacks, avgSellerRating, FEEDBACKSELLER, ca.feedback);
	GetFeedback(arbiterFeedBacks, avgArbiterRating, FEEDBACKARBITER, ca.feedback);

	CAliasIndex theSellerAlias;
	CTransaction aliastx;
	bool isExpired = false;
	vector<CAliasIndex> aliasVtxPos;
	if(GetTxAndVtxOfAlias(ca.vchSellerAlias, theSellerAlias, aliastx, aliasVtxPos, isExpired, true))
	{
		theSellerAlias.nHeight = vtxPos.front().nHeight;
		theSellerAlias.GetAliasFromList(aliasVtxPos);
	}
	oEscrow.push_back(Pair("time", sTime));
	oEscrow.push_back(Pair("seller", stringFromVch(ca.vchSellerAlias)));
	oEscrow.push_back(Pair("arbiter", stringFromVch(ca.vchArbiterAlias)));
	oEscrow.push_back(Pair("buyer", stringFromVch(ca.vchBuyerAlias)));
	oEscrow.push_back(Pair("offer", stringFromVch(ca.vchOffer)));
	oEscrow.push_back(Pair("offertitle", stringFromVch(offer.sTitle)));
	oEscrow.push_back(Pair("quantity", strprintf("%d", ca.nQty)));
	int precision = 2;
	float fEscrowFee = getEscrowFee(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, vtxPos.front().nAcceptHeight, precision);
	int64_t nEscrowFee = GetEscrowArbiterFee(offer.GetPrice() * ca.nQty, fEscrowFee);
	CAmount nPricePerUnit = convertSyscoinToCurrencyCode(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, offer.GetPrice(), vtxPos.front().nAcceptHeight, precision);
	CAmount nFee = convertSyscoinToCurrencyCode(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, nEscrowFee, vtxPos.front().nAcceptHeight, precision);

	int extprecision;
	int nExtFeePerByte = getFeePerByte(theSellerAlias.vchAliasPeg, vchFromString(GetPaymentOptionsString(ca.nPaymentOption)), vtxPos.front().nAcceptHeight, extprecision);
	nFee += (nExtFeePerByte*400);
	oEscrow.push_back(Pair("sysrelayfee",strprintf("%ld", (nExtFeePerByte*400))));
	oEscrow.push_back(Pair("relayfee", strprintf("%.*f %s", 8, ValueFromAmount(nExtFeePerByte*400).get_real(), GetPaymentOptionsString(ca.nPaymentOption) )));


	oEscrow.push_back(Pair("sysfee", nEscrowFee));
	oEscrow.push_back(Pair("systotal", (offer.GetPrice() * ca.nQty)));
	oEscrow.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() )));
	oEscrow.push_back(Pair("fee", strprintf("%.*f", 8, ValueFromAmount(nFee).get_real() )));

	oEscrow.push_back(Pair("total", strprintf("%.*f", precision, ValueFromAmount(nFee + (nPricePerUnit* ca.nQty)).get_real() )));
	oEscrow.push_back(Pair("currency", stringFromVch(offer.sCurrencyCode)));


	string strExtId = "";
	if(ca.nPaymentOption != PAYMENTOPTION_SYS && !vtxPos.front().rawTx.empty())
	{
		CTransaction fundingTx;
		if (DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
		{
			strExtId = fundingTx.GetHash().GetHex();
		}
	}
	oEscrow.push_back(Pair("exttxid", strExtId));
	string strRedeemTxId = "";
	if(!ca.redeemTxId.IsNull())
		strRedeemTxId = ca.redeemTxId.GetHex();
    oEscrow.push_back(Pair("paymentoption", (int)ca.nPaymentOption));
    oEscrow.push_back(Pair("paymentoption_display", GetPaymentOptionsString(ca.nPaymentOption)));
	oEscrow.push_back(Pair("redeem_txid", strRedeemTxId));
    oEscrow.push_back(Pair("txid", ca.txHash.GetHex()));
    oEscrow.push_back(Pair("height", sHeight));
	string strMessage = string("");
	if(!DecryptMessage(theSellerAlias.vchPubKey, ca.vchPaymentMessage, strMessage))
		strMessage = _("Encrypted for owner of offer");
	oEscrow.push_back(Pair("pay_message", strMessage));
	int expired_block = ca.nHeight + GetEscrowExpirationDepth();
	int expired = 0;
    if(expired_block < chainActive.Tip()->nHeight && ca.op == OP_ESCROW_COMPLETE)
	{
		expired = 1;
	}
	bool escrowRelease = false;
	bool escrowRefund = false;
	if(ca.op == OP_ESCROW_COMPLETE)
	{
		for(unsigned int i = vtxPos.size() - 1; i >= 0;i--)
		{
			if(vtxPos[i].op == OP_ESCROW_RELEASE)
			{
				escrowRelease = true;
				break;
			}
			else if(vtxPos[i].op == OP_ESCROW_REFUND)
			{
				escrowRefund = true;
				break;
			}
		}
	}
	string status = "unknown";
	if(ca.op == OP_ESCROW_ACTIVATE)
		status = "in escrow";
	else if(ca.op == OP_ESCROW_RELEASE && vvch[1] == vchFromString("0"))
		status = "escrow released";
	else if(ca.op == OP_ESCROW_RELEASE && vvch[1] == vchFromString("1"))
		status = "escrow release complete";
	else if(ca.op == OP_ESCROW_COMPLETE && escrowRelease)
		status = "escrow release complete";
	else if(ca.op == OP_ESCROW_REFUND && vvch[1] == vchFromString("0"))
		status = "escrow refunded";
	else if(ca.op == OP_ESCROW_REFUND && vvch[1] == vchFromString("1"))
		status = "escrow refund complete";
	else if(ca.op == OP_ESCROW_COMPLETE && escrowRefund)
		status = "escrow refund complete";
	if(ca.bPaymentAck)
		status += " (acknowledged)";
	oEscrow.push_back(Pair("expired", expired));
	oEscrow.push_back(Pair("status", status));
	UniValue oBuyerFeedBack(UniValue::VARR);
	for(unsigned int i =0;i<buyerFeedBacks.size();i++)
	{
		UniValue oFeedback(UniValue::VOBJ);
		string sFeedbackTime;
		CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
		if (pindex) {
			sFeedbackTime = strprintf("%llu", pindex->nTime);
		}
		oFeedback.push_back(Pair("txid", buyerFeedBacks[i].txHash.GetHex()));
		oFeedback.push_back(Pair("time", sFeedbackTime));
		oFeedback.push_back(Pair("rating", buyerFeedBacks[i].nRating));
		oFeedback.push_back(Pair("feedbackuser", buyerFeedBacks[i].nFeedbackUserFrom));
		oFeedback.push_back(Pair("feedback", stringFromVch(buyerFeedBacks[i].vchFeedback)));
		oBuyerFeedBack.push_back(oFeedback);
	}
	oEscrow.push_back(Pair("buyer_feedback", oBuyerFeedBack));
	oEscrow.push_back(Pair("avg_buyer_rating", avgBuyerRating));
	UniValue oSellerFeedBack(UniValue::VARR);
	for(unsigned int i =0;i<sellerFeedBacks.size();i++)
	{
		UniValue oFeedback(UniValue::VOBJ);
		string sFeedbackTime;
		CBlockIndex *pindex = chainActive[sellerFeedBacks[i].nHeight];
		if (pindex) {
			sFeedbackTime = strprintf("%llu", pindex->nTime);
		}
		oFeedback.push_back(Pair("txid", sellerFeedBacks[i].txHash.GetHex()));
		oFeedback.push_back(Pair("time", sFeedbackTime));
		oFeedback.push_back(Pair("rating", sellerFeedBacks[i].nRating));
		oFeedback.push_back(Pair("feedbackuser", sellerFeedBacks[i].nFeedbackUserFrom));
		oFeedback.push_back(Pair("feedback", stringFromVch(sellerFeedBacks[i].vchFeedback)));
		oSellerFeedBack.push_back(oFeedback);
	}
	oEscrow.push_back(Pair("seller_feedback", oSellerFeedBack));
	oEscrow.push_back(Pair("avg_seller_rating", avgSellerRating));
	UniValue oArbiterFeedBack(UniValue::VARR);
	for(unsigned int i =0;i<arbiterFeedBacks.size();i++)
	{
		UniValue oFeedback(UniValue::VOBJ);
		string sFeedbackTime;
		CBlockIndex *pindex = chainActive[arbiterFeedBacks[i].nHeight];
		if (pindex) {
			sFeedbackTime = strprintf("%llu", pindex->nTime);
		}
		oFeedback.push_back(Pair("txid", arbiterFeedBacks[i].txHash.GetHex()));
		oFeedback.push_back(Pair("time", sFeedbackTime));
		oFeedback.push_back(Pair("rating", arbiterFeedBacks[i].nRating));
		oFeedback.push_back(Pair("feedbackuser", arbiterFeedBacks[i].nFeedbackUserFrom));
		oFeedback.push_back(Pair("feedback", stringFromVch(arbiterFeedBacks[i].vchFeedback)));
		oArbiterFeedBack.push_back(oFeedback);
	}
	oEscrow.push_back(Pair("arbiter_feedback", oArbiterFeedBack));
	oEscrow.push_back(Pair("avg_arbiter_rating", avgArbiterRating));
	unsigned int ratingCount = 0;
	if(avgArbiterRating > 0)
		ratingCount++;
	if(avgSellerRating > 0)
		ratingCount++;
	if(avgBuyerRating > 0)
		ratingCount++;
	oEscrow.push_back(Pair("avg_rating_count", (int)ratingCount));
	if(ratingCount == 0)
		ratingCount = 1;
	float totalAvgRating = roundf((avgArbiterRating+avgSellerRating+avgBuyerRating)/(float)ratingCount);
	oEscrow.push_back(Pair("avg_rating", (int)totalAvgRating));
    return oEscrow;
}

UniValue escrowlist(const UniValue& params, bool fHelp) {
   if (fHelp || 2 < params.size() || params.size() < 1)
        throw runtime_error("escrowlist <alias> [<escrow>]\n"
                "list escrows that an alias is involved in");
	vector<unsigned char> vchEscrow;
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
    if (params.size() >= 2)
        vchNameUniq = vchFromValue(params[1]);

    UniValue oRes(UniValue::VARR);

    vector<unsigned char> vchValue;
    vector<pair<vector<unsigned char>, CEscrow> > escrowScan;
    if (!pescrowdb->ScanEscrows(vchNameUniq, name, 1000, escrowScan))
        throw runtime_error("scan failed");
    pair<vector<unsigned char>, CEscrow> pairScan;
    BOOST_FOREACH(pairScan, escrowScan) {
		const CEscrow &escrow = pairScan.second;
		const string &escrowStr = stringFromVch(pairScan.first);
		vector<CEscrow> vtxEscrowPos;
		CTransaction tx;
		if (!GetSyscoinTransaction(escrow.nHeight, escrow.txHash, tx, Params().GetConsensus())) 
			continue;
		if (!pescrowdb->ReadEscrow(pairScan.first, vtxEscrowPos) || vtxEscrowPos.empty())
			continue;
        vector<vector<unsigned char> > vvch;
        int op, nOut;
        if (!DecodeEscrowTx(tx, op, nOut, vvch)
        	|| !IsEscrowOp(op) )
            continue;
		int expired = 0;
		int expired_block = 0;

		bool escrowRelease = false;
		bool escrowRefund = false;

		if(escrow.op == OP_ESCROW_COMPLETE)
		{
			for(unsigned int i = vtxEscrowPos.size() - 1; i >= 0;i--)
			{
				if(vtxEscrowPos[i].op == OP_ESCROW_RELEASE)
				{
					escrowRelease = true;
					break;
				}
				else if(vtxEscrowPos[i].op == OP_ESCROW_REFUND)
				{
					escrowRefund = true;
					break;
				}
			}
		}
		CAliasIndex theSellerAlias;
		CTransaction aliassellertx;
		bool issellerExpired = false;
		vector<CAliasIndex> aliasVtxPos;
		if(GetTxAndVtxOfAlias(escrow.vchSellerAlias, theSellerAlias, aliassellertx, aliasVtxPos, issellerExpired, true))
		{
			theSellerAlias.nHeight = vtxPos.front().nHeight;
			theSellerAlias.GetAliasFromList(aliasVtxPos);
		}
		int nHeight;
		COffer offer;
		CTransaction offertx;
		vector<COffer> offerVtxPos;
		GetTxAndVtxOfOffer(escrow.vchOffer, offer, offertx, offerVtxPos, true);

		nHeight = vtxEscrowPos.front().nAcceptHeight;
		offer.nHeight = nHeight;
		offer.GetOfferFromList(offerVtxPos);


        // build the output
        UniValue oName(UniValue::VOBJ);
        oName.push_back(Pair("escrow", escrowStr));
		string sTime;
		CBlockIndex *pindex = chainActive[escrow.nHeight];
		if (pindex) {
			sTime = strprintf("%llu", pindex->nTime);
		}
		int avgBuyerRating, avgSellerRating, avgArbiterRating;
		vector<CFeedback> buyerFeedBacks, sellerFeedBacks, arbiterFeedBacks;
		GetFeedback(buyerFeedBacks, avgBuyerRating, FEEDBACKBUYER, escrow.feedback);
		GetFeedback(sellerFeedBacks, avgSellerRating, FEEDBACKSELLER, escrow.feedback);
		GetFeedback(arbiterFeedBacks, avgArbiterRating, FEEDBACKARBITER, escrow.feedback);



		oName.push_back(Pair("time", sTime));
		oName.push_back(Pair("seller", stringFromVch(escrow.vchSellerAlias)));
		oName.push_back(Pair("arbiter", stringFromVch(escrow.vchArbiterAlias)));
		oName.push_back(Pair("buyer", stringFromVch(escrow.vchBuyerAlias)));
		oName.push_back(Pair("offer", stringFromVch(escrow.vchOffer)));
		oName.push_back(Pair("offertitle", stringFromVch(offer.sTitle)));
		int precision = 2;
		float fEscrowFee = getEscrowFee(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, nHeight, precision);
		int64_t nEscrowFee = GetEscrowArbiterFee(offer.GetPrice() * escrow.nQty, fEscrowFee);
		CAmount nPricePerUnit = convertSyscoinToCurrencyCode(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, offer.GetPrice(), nHeight, precision);
		CAmount nFee = convertSyscoinToCurrencyCode(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, nEscrowFee, nHeight, precision);

		int extprecision;
		int nExtFeePerByte = getFeePerByte(theSellerAlias.vchAliasPeg, vchFromString(GetPaymentOptionsString(escrow.nPaymentOption)), nHeight, extprecision);
		nFee += (nExtFeePerByte*400);
		oName.push_back(Pair("sysrelayfee",strprintf("%ld", (nExtFeePerByte*400))));
		oName.push_back(Pair("relayfee", strprintf("%.*f %s", 8, ValueFromAmount(nExtFeePerByte*400).get_real(), GetPaymentOptionsString(escrow.nPaymentOption) )));
	
		oName.push_back(Pair("sysfee", nEscrowFee));
		oName.push_back(Pair("systotal", (offer.GetPrice() * escrow.nQty)));
		oName.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() )));
		oName.push_back(Pair("fee", strprintf("%.*f", 8, ValueFromAmount(nFee).get_real() )));
		oName.push_back(Pair("total", strprintf("%.*f", precision, ValueFromAmount(nFee + (nPricePerUnit* escrow.nQty)).get_real() )));
		oName.push_back(Pair("currency", stringFromVch(offer.sCurrencyCode)));
		string strExtId = "";
		if(escrow.nPaymentOption != PAYMENTOPTION_SYS && !vtxPos.front().rawTx.empty())
		{
			CTransaction fundingTx;
			if (DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
			{
				strExtId = fundingTx.GetHash().GetHex();
			}
		}
		oName.push_back(Pair("exttxid", strExtId));
        oName.push_back(Pair("paymentoption", (int)escrow.nPaymentOption));
        oName.push_back(Pair("paymentoption_display", GetPaymentOptionsString(escrow.nPaymentOption)));
		string strRedeemTxId = "";
		if(!escrow.redeemTxId.IsNull())
			strRedeemTxId = escrow.redeemTxId.GetHex();
		oName.push_back(Pair("redeem_txid", strRedeemTxId));
		expired_block = escrow.nHeight + GetEscrowExpirationDepth();
        if(expired_block < chainActive.Tip()->nHeight && escrow.op == OP_ESCROW_COMPLETE)
		{
			expired = 1;
		}

		string status = "unknown";
		if(escrow.op == OP_ESCROW_ACTIVATE)
			status = "in escrow";
		else if(escrow.op == OP_ESCROW_RELEASE && vvch[1] == vchFromString("0"))
			status = "escrow released";
		else if(escrow.op == OP_ESCROW_RELEASE && vvch[1] == vchFromString("1"))
			status = "escrow release complete";
		else if(escrow.op == OP_ESCROW_COMPLETE && escrowRelease)
			status = "escrow release complete";
		else if(escrow.op == OP_ESCROW_REFUND && vvch[1] == vchFromString("0"))
			status = "escrow refunded";
		else if(escrow.op == OP_ESCROW_REFUND && vvch[1] == vchFromString("1"))
			status = "escrow refund complete";
		else if(escrow.op == OP_ESCROW_COMPLETE && escrowRefund)
			status = "escrow refund complete";
		if(escrow.bPaymentAck)
			status += " (acknowledged)";

		UniValue oBuyerFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<buyerFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("txid", buyerFeedBacks[i].txHash.GetHex()));
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", buyerFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", buyerFeedBacks[i].nFeedbackUserFrom));
			oFeedback.push_back(Pair("feedback", stringFromVch(buyerFeedBacks[i].vchFeedback)));
			oBuyerFeedBack.push_back(oFeedback);
		}
		oName.push_back(Pair("buyer_feedback", oBuyerFeedBack));
		oName.push_back(Pair("avg_buyer_rating", avgBuyerRating));
		UniValue oSellerFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<sellerFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[sellerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("txid", sellerFeedBacks[i].txHash.GetHex()));
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", sellerFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", sellerFeedBacks[i].nFeedbackUserFrom));
			oFeedback.push_back(Pair("feedback", stringFromVch(sellerFeedBacks[i].vchFeedback)));
			oSellerFeedBack.push_back(oFeedback);
		}
		oName.push_back(Pair("seller_feedback", oSellerFeedBack));
		oName.push_back(Pair("avg_seller_rating", avgSellerRating));
		UniValue oArbiterFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<arbiterFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[arbiterFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("txid", arbiterFeedBacks[i].txHash.GetHex()));
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", arbiterFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", arbiterFeedBacks[i].nFeedbackUserFrom));
			oFeedback.push_back(Pair("feedback", stringFromVch(arbiterFeedBacks[i].vchFeedback)));
			oArbiterFeedBack.push_back(oFeedback);
		}
		oName.push_back(Pair("arbiter_feedback", oArbiterFeedBack));
		oName.push_back(Pair("avg_arbiter_rating", avgArbiterRating));
		unsigned int ratingCount = 0;
		if(avgArbiterRating > 0)
			ratingCount++;
		if(avgSellerRating > 0)
			ratingCount++;
		if(avgBuyerRating > 0)
			ratingCount++;
		oName.push_back(Pair("avg_rating_count", (int)ratingCount));
		if(ratingCount == 0)
			ratingCount = 1;
		float totalAvgRating = roundf((avgArbiterRating+avgSellerRating+avgBuyerRating)/(float)ratingCount);
		oName.push_back(Pair("avg_rating", (int)totalAvgRating));
		oName.push_back(Pair("status", status));
		oName.push_back(Pair("expired", expired));
		oName.push_back(Pair("ismine", IsSyscoinTxMine(aliastx, "alias") ? "true" : "false"));
		oRes.push_back(oName);
	}
    return oRes;
}


UniValue escrowhistory(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("escrowhistory <escrow>\n"
                "List all stored values of an escrow.\n");

    UniValue oRes(UniValue::VARR);
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
    string escrow = stringFromVch(vchEscrow);

    {
        vector<CEscrow> vtxPos;
        if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
            throw runtime_error("failed to read from escrow DB");

        CEscrow txPos2;
        uint256 txHash;
        uint256 blockHash;
        BOOST_FOREACH(txPos2, vtxPos) {

            txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetSyscoinTransaction(txPos2.nHeight, txHash, tx, Params().GetConsensus())) {
				error("could not read txpos");
				continue;
			}

			COffer offer;
			CTransaction offertx;
			vector<COffer> offerVtxPos;
			GetTxAndVtxOfOffer(txPos2.vchOffer, offer, offertx, offerVtxPos, true);
			offer.nHeight = vtxPos.front().nAcceptHeight;
			offer.GetOfferFromList(offerVtxPos);
            // decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeEscrowTx(tx, op, nOut, vvch)
            	|| !IsEscrowOp(op) )
                continue;
			CAliasIndex theSellerAlias;
			CTransaction aliassellertx;
			bool issellerExpired = false;
			vector<CAliasIndex> aliasVtxPos;
			if(GetTxAndVtxOfAlias(txPos2.vchSellerAlias, theSellerAlias, aliassellertx, aliasVtxPos, issellerExpired, true))
			{
				theSellerAlias.nHeight = vtxPos.front().nHeight;
				theSellerAlias.GetAliasFromList(aliasVtxPos);
			}

			bool escrowRelease = false;
			bool escrowRefund = false;
			if(txPos2.op == OP_ESCROW_COMPLETE)
			{
				for(int i = vtxPos.size() - 1; i >= 0;i--)
				{
					if(vtxPos[i].op == OP_ESCROW_RELEASE)
					{
						escrowRelease = true;
						break;
					}
					else if(vtxPos[i].op == OP_ESCROW_REFUND)
					{
						escrowRefund = true;
						break;
					}
				}
			}
			int expired = 0;
            UniValue oEscrow(UniValue::VOBJ);
            uint64_t nHeight;
			nHeight = txPos2.nHeight;
			oEscrow.push_back(Pair("escrow", escrow));
			string opName = escrowFromOp(txPos2.op);
			CEscrow escrow(tx);
			if(escrow.bPaymentAck)
				opName += "("+_("acknowledged")+")";
			else if(!escrow.feedback.empty())
				opName += "("+_("feedback")+")";
			oEscrow.push_back(Pair("escrowtype", opName));

			oEscrow.push_back(Pair("txid", tx.GetHash().GetHex()));
			oEscrow.push_back(Pair("seller", stringFromVch(txPos2.vchSellerAlias)));
			oEscrow.push_back(Pair("arbiter", stringFromVch(txPos2.vchArbiterAlias)));
			oEscrow.push_back(Pair("buyer", stringFromVch(txPos2.vchBuyerAlias)));
			oEscrow.push_back(Pair("offer", stringFromVch(txPos2.vchOffer)));
			oEscrow.push_back(Pair("offertitle", stringFromVch(offer.sTitle)));
			int precision = 2;
			float fEscrowFee = getEscrowFee(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, vtxPos.front().nAcceptHeight, precision);
			int64_t nEscrowFee = GetEscrowArbiterFee(offer.GetPrice() * txPos2.nQty, fEscrowFee);
			CAmount nPricePerUnit = convertSyscoinToCurrencyCode(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, offer.GetPrice(),  vtxPos.front().nAcceptHeight, precision);
			CAmount nFee = convertSyscoinToCurrencyCode(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, nEscrowFee, vtxPos.front().nAcceptHeight, precision);

			int extprecision;
			int nExtFeePerByte = getFeePerByte(theSellerAlias.vchAliasPeg, vchFromString(GetPaymentOptionsString(txPos2.nPaymentOption)), vtxPos.front().nAcceptHeight, extprecision);
			nFee += (nExtFeePerByte*400);
			oEscrow.push_back(Pair("sysrelayfee",strprintf("%ld", nExtFeePerByte*400)));
			oEscrow.push_back(Pair("relayfee", strprintf("%.*f %s", 8, ValueFromAmount(nExtFeePerByte*400).get_real(), GetPaymentOptionsString(txPos2.nPaymentOption) )));
		
			oEscrow.push_back(Pair("sysfee", nEscrowFee));
			oEscrow.push_back(Pair("systotal", (offer.GetPrice() * txPos2.nQty)));
			oEscrow.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() )));
			oEscrow.push_back(Pair("fee", strprintf("%.*f", 8, ValueFromAmount(nFee).get_real() )));
			oEscrow.push_back(Pair("total", strprintf("%.*f", precision, ValueFromAmount(nFee + (nPricePerUnit* txPos2.nQty)).get_real() )));
			oEscrow.push_back(Pair("currency", stringFromVch(offer.sCurrencyCode)));
			string strExtId = "";
			if(txPos2.nPaymentOption != PAYMENTOPTION_SYS && !vtxPos.front().rawTx.empty())
			{
				CTransaction fundingTx;
				if (DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
				{
					strExtId = fundingTx.GetHash().GetHex();
				}
			}
			oEscrow.push_back(Pair("exttxid", strExtId));
            oEscrow.push_back(Pair("paymentoption", (int)txPos2.nPaymentOption));
            oEscrow.push_back(Pair("paymentoption_display", GetPaymentOptionsString(txPos2.nPaymentOption)));
			string strRedeemTxId = "";
			if(!txPos2.redeemTxId.IsNull())
				strRedeemTxId = txPos2.redeemTxId.GetHex();
			oEscrow.push_back(Pair("redeem_txid", strRedeemTxId));
			if(nHeight + GetEscrowExpirationDepth() - chainActive.Tip()->nHeight <= 0  && txPos2.op == OP_ESCROW_COMPLETE)
			{
				expired = 1;
			}

			string status = "unknown";

			if(txPos2.op == OP_ESCROW_ACTIVATE)
				status = "in escrow";
			else if(txPos2.op == OP_ESCROW_RELEASE && vvch[1] == vchFromString("0"))
				status = "escrow released";
			else if(txPos2.op == OP_ESCROW_RELEASE && vvch[1] == vchFromString("1"))
				status = "escrow release complete";
			else if(txPos2.op == OP_ESCROW_COMPLETE && escrowRelease)
				status = "escrow release complete";
			else if(txPos2.op == OP_ESCROW_REFUND && vvch[1] == vchFromString("0"))
				status = "escrow refunded";
			else if(txPos2.op == OP_ESCROW_REFUND && vvch[1] == vchFromString("1"))
				status = "escrow refund complete";
			else if(txPos2.op == OP_ESCROW_COMPLETE && escrowRefund)
				status = "escrow refund complete";
			if(txPos2.bPaymentAck)
				status += " (acknowledged)";
			oEscrow.push_back(Pair("status", status));
			oEscrow.push_back(Pair("expired", expired));
			oEscrow.push_back(Pair("height", strprintf("%d", nHeight)));
			oRes.push_back(oEscrow);
        }

    }
    return oRes;
}
UniValue escrowfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 2)
		throw runtime_error(
				"escrowfilter [[[[[regexp]] from=0]}\n"
						"scan and filter escrows\n"
						"[regexp] : apply [regexp] on escrows, empty means all escrows\n"
						"[from] : show results from this GUID [from], 0 means first.\n"
						"[escrowfilter] : shows all escrows that are safe to display (not on the ban list)\n"
						"escrowfilter \"\" 5 # list escrows updated in last 5 blocks\n"
						"escrowfilter \"^escrow\" # list all excrows starting with \"escrow\"\n"
						"escrowfilter 36000 0 0 stat # display stats (number of escrows) on active escrows\n");

	vector<unsigned char> vchEscrow;
	string strRegexp;

	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		vchEscrow = vchFromValue(params[1]);

	UniValue oRes(UniValue::VARR);


    vector<pair<vector<unsigned char>, CEscrow> > escrowScan;
    if (!pescrowdb->ScanEscrows(vchEscrow, strRegexp, 25, escrowScan))
        throw runtime_error("scan failed");
    pair<vector<unsigned char>, CEscrow> pairScan;
    BOOST_FOREACH(pairScan, escrowScan) {
		const CEscrow &txEscrow = pairScan.second;
		const string &escrow = stringFromVch(pairScan.first);
		vector<COffer> offerVtxPos;
		vector<CEscrow> vtxPos;
		COffer offer;
        int nHeight = txEscrow.nHeight;
		CTransaction tx;
		if (!GetSyscoinTransaction(nHeight, txEscrow.txHash, tx, Params().GetConsensus())) {
			continue;
		}
        vector<vector<unsigned char> > vvch;
        int op, nOut;
        if (!DecodeEscrowTx(tx, op, nOut, vvch)
        	|| !IsEscrowOp(op) )
            continue;
		int avgBuyerRating, avgSellerRating, avgArbiterRating;
		if (!pescrowdb->ReadEscrow(pairScan.first, vtxPos) || vtxPos.empty())
			continue;
		bool escrowRelease = false;
		bool escrowRefund = false;
		if(txEscrow.op == OP_ESCROW_COMPLETE)
		{
			for(int i = vtxPos.size() - 1; i >= 0;i--)
			{
				if(vtxPos[i].op == OP_ESCROW_RELEASE)
				{
					escrowRelease = true;
					break;
				}
				else if(vtxPos[i].op == OP_ESCROW_REFUND)
				{
					escrowRefund = true;
					break;
				}
			}
		}
		if (pofferdb->ReadOffer(txEscrow.vchOffer, offerVtxPos) && !offerVtxPos.empty())
		{
			offer.nHeight = vtxPos.front().nAcceptHeight;
			offer.GetOfferFromList(offerVtxPos);
		}
		CAliasIndex theSellerAlias;
		CTransaction aliassellertx;
		bool issellerExpired = false;
		vector<CAliasIndex> aliasVtxPos;
		if(GetTxAndVtxOfAlias(txEscrow.vchSellerAlias, theSellerAlias, aliassellertx, aliasVtxPos, issellerExpired, true))
		{
			theSellerAlias.nHeight = vtxPos.front().nHeight;
			theSellerAlias.GetAliasFromList(aliasVtxPos);
		}
		vector<CFeedback> buyerFeedBacks, sellerFeedBacks, arbiterFeedBacks;
		GetFeedback(buyerFeedBacks, avgBuyerRating, FEEDBACKBUYER, txEscrow.feedback);
		GetFeedback(sellerFeedBacks, avgSellerRating, FEEDBACKSELLER, txEscrow.feedback);
		GetFeedback(arbiterFeedBacks, avgArbiterRating, FEEDBACKARBITER, txEscrow.feedback);

        UniValue oEscrow(UniValue::VOBJ);
        oEscrow.push_back(Pair("escrow", escrow));
		string sTime;
		CBlockIndex *pindex = chainActive[txEscrow.nHeight];
		if (pindex) {
			sTime = strprintf("%llu", pindex->nTime);
		}
		oEscrow.push_back(Pair("time", sTime));

		oEscrow.push_back(Pair("seller", stringFromVch(txEscrow.vchSellerAlias)));
		oEscrow.push_back(Pair("arbiter", stringFromVch(txEscrow.vchArbiterAlias)));
		oEscrow.push_back(Pair("buyer", stringFromVch(txEscrow.vchBuyerAlias)));
		oEscrow.push_back(Pair("offer", stringFromVch(txEscrow.vchOffer)));
		oEscrow.push_back(Pair("offertitle", stringFromVch(offer.sTitle)));

		string status = "unknown";

		if(txEscrow.op == OP_ESCROW_ACTIVATE)
			status = "in escrow";
		else if(txEscrow.op == OP_ESCROW_RELEASE && vvch[1] == vchFromString("0"))
			status = "escrow released";
		else if(txEscrow.op == OP_ESCROW_RELEASE && vvch[1] == vchFromString("1"))
			status = "escrow release complete";
		else if(txEscrow.op == OP_ESCROW_COMPLETE && escrowRelease)
			status = "escrow release complete";
		else if(txEscrow.op == OP_ESCROW_REFUND && vvch[1] == vchFromString("0"))
			status = "escrow refunded";
		else if(txEscrow.op == OP_ESCROW_REFUND && vvch[1] == vchFromString("1"))
			status = "escrow refund complete";
		else if(txEscrow.op == OP_ESCROW_COMPLETE && escrowRefund)
			status = "escrow refund complete";
		if(txEscrow.bPaymentAck)
			status += " (acknowledged)";

		oEscrow.push_back(Pair("status", status));
		int precision = 2;
		float fEscrowFee = getEscrowFee(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, vtxPos.front().nAcceptHeight, precision);
		int64_t nEscrowFee = GetEscrowArbiterFee(offer.GetPrice() * txEscrow.nQty, fEscrowFee);
		CAmount nPricePerUnit = convertSyscoinToCurrencyCode(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, offer.GetPrice(),  vtxPos.front().nAcceptHeight, precision);
		CAmount nFee = convertSyscoinToCurrencyCode(theSellerAlias.vchAliasPeg, offer.sCurrencyCode, nEscrowFee, vtxPos.front().nAcceptHeight, precision);

		int extprecision;
		int nExtFeePerByte = getFeePerByte(theSellerAlias.vchAliasPeg, vchFromString(GetPaymentOptionsString(txEscrow.nPaymentOption)), vtxPos.front().nAcceptHeight, extprecision);
		nFee += (nExtFeePerByte*400);
		oEscrow.push_back(Pair("sysrelayfee",strprintf("%ld", nExtFeePerByte*400)));
		oEscrow.push_back(Pair("relayfee", strprintf("%.*f %s", 8, ValueFromAmount(nExtFeePerByte*400).get_real(), GetPaymentOptionsString(txEscrow.nPaymentOption) )));
	
		oEscrow.push_back(Pair("sysfee", nEscrowFee));
		oEscrow.push_back(Pair("systotal", (offer.GetPrice() * txEscrow.nQty)));
		oEscrow.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() )));
		oEscrow.push_back(Pair("fee", strprintf("%.*f", 8, ValueFromAmount(nFee).get_real() )));
		oEscrow.push_back(Pair("total", strprintf("%.*f", precision, ValueFromAmount(nFee + (nPricePerUnit* txEscrow.nQty)).get_real() )));
		oEscrow.push_back(Pair("currency", stringFromVch(offer.sCurrencyCode)));
		string strExtId = "";
		if(txEscrow.nPaymentOption != PAYMENTOPTION_SYS && !vtxPos.front().rawTx.empty())
		{
			CTransaction fundingTx;
			if (DecodeHexTx(fundingTx,HexStr(vtxPos.front().rawTx)))
			{
				strExtId = fundingTx.GetHash().GetHex();
			}
		}
		oEscrow.push_back(Pair("exttxid", strExtId));
        oEscrow.push_back(Pair("paymentoption", (int)txEscrow.nPaymentOption));
        oEscrow.push_back(Pair("paymentoption_display", GetPaymentOptionsString(txEscrow.nPaymentOption)));
		string strRedeemTxId = "";
		if(!txEscrow.redeemTxId.IsNull())
			strRedeemTxId = txEscrow.redeemTxId.GetHex();
		oEscrow.push_back(Pair("redeem_txid", strRedeemTxId));

		UniValue oBuyerFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<buyerFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", buyerFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", buyerFeedBacks[i].nFeedbackUserFrom));
			oFeedback.push_back(Pair("feedback", stringFromVch(buyerFeedBacks[i].vchFeedback)));
			oBuyerFeedBack.push_back(oFeedback);
		}
		oEscrow.push_back(Pair("buyer_feedback", oBuyerFeedBack));
		oEscrow.push_back(Pair("avg_buyer_rating", avgBuyerRating));
		UniValue oSellerFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<sellerFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[sellerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", sellerFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", sellerFeedBacks[i].nFeedbackUserFrom));
			oFeedback.push_back(Pair("feedback", stringFromVch(sellerFeedBacks[i].vchFeedback)));
			oSellerFeedBack.push_back(oFeedback);
		}
		oEscrow.push_back(Pair("seller_feedback", oSellerFeedBack));
		oEscrow.push_back(Pair("avg_seller_rating", avgSellerRating));
		UniValue oArbiterFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<arbiterFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[arbiterFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", arbiterFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", arbiterFeedBacks[i].nFeedbackUserFrom));
			oFeedback.push_back(Pair("feedback", stringFromVch(arbiterFeedBacks[i].vchFeedback)));
			oArbiterFeedBack.push_back(oFeedback);
		}
		oEscrow.push_back(Pair("arbiter_feedback", oArbiterFeedBack));
		oEscrow.push_back(Pair("avg_arbiter_rating", avgArbiterRating));
		unsigned int ratingCount = 0;
		if(avgArbiterRating > 0)
			ratingCount++;
		if(avgSellerRating > 0)
			ratingCount++;
		if(avgBuyerRating > 0)
			ratingCount++;
		oEscrow.push_back(Pair("avg_rating_count", (int)ratingCount));
		if(ratingCount == 0)
			ratingCount = 1;
		float totalAvgRating = roundf((avgArbiterRating+avgSellerRating+avgBuyerRating)/(float)ratingCount);
		oEscrow.push_back(Pair("avg_rating", (int)totalAvgRating));
        oRes.push_back(oEscrow);
    }


	return oRes;
}
void EscrowTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry)
{
	
	CEscrow escrow;
	if(!escrow.UnserializeFromData(vchData, vchHash))
		return;

	CTransaction escrowtx;
	CEscrow dbEscrow;
	GetTxOfEscrow(escrow.vchEscrow, dbEscrow, escrowtx);


	string noDifferentStr = _("<No Difference Detected>");
	CEscrow escrowop(escrowtx);
	string opName = escrowFromOp(escrowop.op);
	if(escrowop.bPaymentAck)
		opName += "("+_("acknowledged")+")";
	else if(!escrowop.feedback.empty())
		opName += "("+_("feedback")+")";
	entry.push_back(Pair("txtype", opName));
	entry.push_back(Pair("escrow", stringFromVch(escrow.vchEscrow)));

	string ackValue = noDifferentStr;
	if(escrow.bPaymentAck && escrow.bPaymentAck != dbEscrow.bPaymentAck)
		ackValue = escrow.bPaymentAck? "true": "false";

	entry.push_back(Pair("paymentacknowledge", ackValue));	

	entry.push_back(Pair("linkalias", stringFromVch(escrow.vchLinkAlias)));

	string feedbackValue = noDifferentStr;
	if(!escrow.feedback.empty())
		feedbackValue = _("Escrow feedback was given");
	entry.push_back(Pair("feedback", feedbackValue));
}
