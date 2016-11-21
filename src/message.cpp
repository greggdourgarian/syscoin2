#include "message.h"
#include "alias.h"
#include "cert.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "base58.h"
#include "core_io.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "chainparams.h"
#include <boost/algorithm/hex.hpp>
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <functional> 
using namespace std;
extern void SendMoneySyscoin(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInAlias=NULL, bool syscoinMultiSigTx=false, const CCoinControl* coinControl=NULL);
void PutToMessageList(std::vector<CMessage> &messageList, CMessage& index) {
	int i = messageList.size() - 1;
	BOOST_REVERSE_FOREACH(CMessage &o, messageList) {
        if(index.nHeight != 0 && o.nHeight == index.nHeight) {
        	messageList[i] = index;
            return;
        }
        else if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	messageList[i] = index;
            return;
        }
        i--;
	}
    messageList.push_back(index);
}
bool IsMessageOp(int op) {
    return op == OP_MESSAGE_ACTIVATE;
}

int GetMessageExpirationDepth() {
	#ifdef ENABLE_DEBUGRPC
    return 1440;
  #else
    return 525600;
  #endif
}


string messageFromOp(int op) {
    switch (op) {
    case OP_MESSAGE_ACTIVATE:
        return "messageactivate";
    default:
        return "<unknown message op>";
    }
}
bool CMessage::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsMessage(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsMessage >> *this;
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	const vector<unsigned char> &vchMsgData = Serialize();
	uint256 calculatedHash = Hash(vchMsgData.begin(), vchMsgData.end());
	vector<unsigned char> vchRandMsg= vchFromValue(calculatedHash.GetHex());
	if(vchRandMsg != vchHash)
	{
		SetNull();
        return false;
	}
	return true;
}
bool CMessage::UnserializeFromTx(const CTransaction &tx) {
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
const vector<unsigned char> CMessage::Serialize() {
    CDataStream dsMessage(SER_NETWORK, PROTOCOL_VERSION);
    dsMessage << *this;
    const vector<unsigned char> vchData(dsMessage.begin(), dsMessage.end());
    return vchData;

}
bool CMessageDB::CleanupDatabase()
{
	int nMaxAge  = GetMessageExpirationDepth();
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->SeekToFirst();
	vector<CMessage> vtxPos;
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "messagei") {
            	const vector<unsigned char> &vchMyMessage= key.second;         
				pcursor->GetValue(vtxPos);	
				if (vtxPos.empty()){
					EraseMessage(vchMyMessage);
					continue;
				}
				const CMessage &txPos = vtxPos.back();
  				if ((chainActive.Tip()->nHeight - txPos.nHeight) >= nMaxAge)
				{
					EraseMessage(vchMyMessage);
				} 
				
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
	return true;
}

bool CMessageDB::ScanRecvMessages(const std::vector<unsigned char>& vchMessage, const vector<string>& keyWordArray,unsigned int nMax,
        std::vector<CMessage> & messageScan) {
	int nMaxAge  = GetMessageExpirationDepth();
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	if(!vchMessage.empty())
		pcursor->Seek(make_pair(string("messagei"), vchMessage));
	else
		pcursor->SeekToFirst();
	pair<string, vector<unsigned char> > key;
	 vector<CMessage> vtxPos;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            if (pcursor->GetKey(key) && key.first == "messagei") {
                const vector<unsigned char> &vchMyMessage = key.second;     
                pcursor->GetValue(vtxPos);
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CMessage &txPos = vtxPos.back();
  				if (chainActive.Tip()->nHeight - txPos.nHeight >= nMaxAge)
				{
					pcursor->Next();
					continue;
				}

				if(keyWordArray.size() > 0)
				{
					string toAliasLower = stringFromVch(txPos.vchAliasTo);
					if (std::find(keyWordArray.begin(), keyWordArray.end(), toAliasLower) == keyWordArray.end())
					{
						pcursor->Next();
						continue;
					}
				}
				if(vchMessage.size() > 0)
				{
					if(vchMyMessage != vchMessage)
					{
						pcursor->Next();
						continue;
					}
				}
                messageScan.push_back(txPos);
            }
            if (messageScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}

int IndexOfMessageOutput(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return -1;
    vector<vector<unsigned char> > vvch;
	int op;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeMessageScript(out.scriptPubKey, op, vvch)) {
			return i;
		}
	}
	return -1;
}


bool GetTxOfMessage(const vector<unsigned char> &vchMessage,
        CMessage& txPos, CTransaction& tx) {
    vector<CMessage> vtxPos;
    if (!pmessagedb->ReadMessage(vchMessage, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (nHeight + GetMessageExpirationDepth()
            < chainActive.Tip()->nHeight) {
        string message = stringFromVch(vchMessage);
        LogPrintf("GetTxOfMessage(%s) : expired", message.c_str());
        return false;
    }

    if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfMessage() : could not read tx from disk");

    return true;
}
bool DecodeAndParseMessageTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CMessage message;
	bool decode = DecodeMessageTx(tx, op, nOut, vvch);
	bool parse = message.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeMessageTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeMessageScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
	if (!found) vvch.clear();
    return found;
}

bool DecodeMessageScript(const CScript& script, int& op,
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
    return IsMessageOp(op);
}

bool DecodeMessageScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeMessageScript(script, op, vvch, pc);
}

CScript RemoveMessageScriptPrefix(const CScript& scriptIn) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeMessageScript(scriptIn, op, vvch, pc))
	{
        throw runtime_error("RemoveMessageScriptPrefix() : could not decode message script");
	}
	
    return CScript(pc, scriptIn.end());
}

bool CheckMessageInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, const CBlock* block, bool dontaddtodb) {
	if(!IsSys21Fork(nHeight))
		return true;	
	if (tx.IsCoinBase())
		return true;
	if (fDebug)
		LogPrintf("*** MESSAGE %d %d %s %s\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			fJustCheck ? "JUSTCHECK" : "BLOCK");
    const COutPoint *prevOutput = NULL;
    const CCoins *prevCoins;

	int prevAliasOp = 0;
	if (tx.nVersion != SYSCOIN_TX_VERSION)
	{
		errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3000 - " + _("Non-Syscoin transaction found");
		return true;
	}
	// unserialize msg from txn, check for valid
	CMessage theMessage;
	CAliasIndex alias;
	CTransaction aliasTx;
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	int nDataOut;
	if(!GetSyscoinData(tx, vchData, vchHash, nDataOut) || !theMessage.UnserializeFromData(vchData, vchHash))
	{
		errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR ERRCODE: 3001 - " + _("Cannot unserialize data inside of this transaction relating to a message");
		return true;
	}

    vector<vector<unsigned char> > vvchPrevAliasArgs;
	if(fJustCheck)
	{	
		if(vvchArgs.size() != 2)
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3002 - " + _("Message arguments incorrect size");
			return error(errorMessage.c_str());
		}
		if(!theMessage.IsNull())
		{
			if(vvchArgs.size() <= 1 || vchHash != vvchArgs[1])
			{
				errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3003 - " + _("Hash provided doesn't match the calculated hash of the data");
				return true;
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
			if (IsAliasOp(pop))
			{
				prevAliasOp = pop;
				vvchPrevAliasArgs = vvch;
				break;
			}
		}	
	}

    // unserialize message UniValue from txn, check for valid
   
	string retError = "";
	if(fJustCheck)
	{
		if (vvchArgs.empty() || vvchArgs[0].size() > MAX_GUID_LENGTH)
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3004 - " + _("Message transaction guid too big");
			return error(errorMessage.c_str());
		}
		if(theMessage.vchSubject.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3005 - " + _("Message subject too long");
			return error(errorMessage.c_str());
		}
		if(theMessage.vchMessageTo.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3006 - " + _("Message too long");
			return error(errorMessage.c_str());
		}
		if(theMessage.vchMessageFrom.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3007 - " + _("Message too long");
			return error(errorMessage.c_str());
		}
		if(!theMessage.vchMessage.empty() && theMessage.vchMessage != vvchArgs[0])
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3008 - " + _("Message guid in data output does not match guid in transaction");
			return error(errorMessage.c_str());
		}
		if(op == OP_MESSAGE_ACTIVATE)
		{
			if(!IsAliasOp(prevAliasOp))
			{
				errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3009 - " + _("Alias not provided as input");
				return error(errorMessage.c_str());
			}
			if (theMessage.vchAliasFrom != vvchPrevAliasArgs[0])
			{
				errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3010 - " + _("Alias guid mismatch");
				return error(errorMessage.c_str());
			}
			if (theMessage.vchMessage != vvchArgs[0])
			{
				errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3011 - " + _("Message guid mismatch");
				return error(errorMessage.c_str());
			}

		}
		else{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3012 - " + _("Message transaction has unknown op");
			return error(errorMessage.c_str());
		}
	}
	// save serialized message for later use
	CMessage serializedMessage = theMessage;


    if (!fJustCheck ) {
		if(!GetTxOfAlias(theMessage.vchAliasTo, alias, aliasTx))
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3013 - " + _("Cannot find alias for the recipient of this message. It may be expired");
			return true;
		}
		if(!GetTxOfAlias(theMessage.vchAliasFrom, alias, aliasTx))
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3014 - " + _("Cannot find alias for the sender of this message. It may be expired");
			return true;		
		}

		vector<CMessage> vtxPos;
		if (pmessagedb->ExistsMessage(vvchArgs[0])) {
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3015 - " + _("This message already exists");
			return true;
		}      
        // set the message's txn-dependent values
		theMessage.txHash = tx.GetHash();
		theMessage.nHeight = nHeight;
		PutToMessageList(vtxPos, theMessage);
        // write message  

		if(!dontaddtodb && !pmessagedb->WriteMessage(vvchArgs[0], vtxPos))
		{
			errorMessage = "SYSCOIN_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3016 - " + _("Failed to write to message DB");
            return error(errorMessage.c_str());
		}
	
		
      			
        // debug
		if(fDebug)
			LogPrintf( "CONNECTED MESSAGE: op=%s message=%s hash=%s height=%d\n",
                messageFromOp(op).c_str(),
                stringFromVch(vvchArgs[0]).c_str(),
                tx.GetHash().ToString().c_str(),
                nHeight);
	}
    return true;
}

UniValue messagenew(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 4 )
        throw runtime_error(
		"messagenew <subject> <message> <fromalias> <toalias>\n"
						"<subject> Subject of message.\n"
						"<message> Message to send to alias.\n"
						"<fromalias> Alias to send message from.\n"
						"<toalias> Alias to send message to.\n"					
                        + HelpRequiringPassphrase());
	vector<unsigned char> vchMySubject = vchFromValue(params[0]);
	vector<unsigned char> vchMyMessage = vchFromValue(params[1]);
	string strFromAddress = params[2].get_str();
	boost::algorithm::to_lower(strFromAddress);
	string strToAddress = params[3].get_str();
	boost::algorithm::to_lower(strToAddress);

	EnsureWalletIsUnlocked();

	CAliasIndex aliasFrom, aliasTo;
	CTransaction aliastx;
	if (!GetTxOfAlias(vchFromString(strFromAddress), aliasFrom, aliastx, true))
		throw runtime_error("SYSCOIN_MESSAGE_RPC_ERROR: ERRCODE: 3500 - " + _("Could not find an alias with this name"));
    if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("SYSCOIN_MESSAGE_RPC_ERROR: ERRCODE: 3501 - " + _("This alias is not yours"));
    }
	const CWalletTx *wtxAliasIn = pwalletMain->GetWalletTx(aliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("SYSCOIN_MESSAGE_RPC_ERROR: ERRCODE: 3502 - " + _("This alias is not in your wallet"));
	CScript scriptPubKeyOrig, scriptPubKeyAliasOrig, scriptPubKey, scriptPubKeyAlias;

	CPubKey FromPubKey = CPubKey(aliasFrom.vchPubKey);
	scriptPubKeyAliasOrig = GetScriptForDestination(FromPubKey.GetID());
	if(aliasFrom.multiSigInfo.vchAliases.size() > 0)
		scriptPubKeyAliasOrig = CScript(aliasFrom.multiSigInfo.vchRedeemScript.begin(), aliasFrom.multiSigInfo.vchRedeemScript.end());
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << aliasFrom.vchAlias <<  aliasFrom.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyAliasOrig;		


	if(!GetTxOfAlias(vchFromString(strToAddress), aliasTo, aliastx, true))
		throw runtime_error("SYSCOIN_MESSAGE_RPC_ERROR: ERRCODE: 3503 - " + _("Failed to read to alias from alias DB"));
	CPubKey ToPubKey = CPubKey(aliasTo.vchPubKey);


    // gather inputs
	vector<unsigned char> vchMessage = vchFromString(GenerateSyscoinGuid());
    // this is a syscoin transaction
    CWalletTx wtx;
	scriptPubKeyOrig= GetScriptForDestination(ToPubKey.GetID());


	string strCipherTextTo;
	if(!EncryptMessage(aliasTo.vchPubKey, vchMyMessage, strCipherTextTo))
	{
		throw runtime_error("SYSCOIN_MESSAGE_RPC_ERROR: ERRCODE: 3504 - " + _("Could not encrypt message data for receiver"));
	}
	string strCipherTextFrom;
	if(!EncryptMessage(aliasFrom.vchPubKey, vchMyMessage, strCipherTextFrom))
	{
		throw runtime_error("SYSCOIN_MESSAGE_RPC_ERROR: ERRCODE: 3505 - " + _("Could not encrypt message data for sender"));
	}

    // build message
    CMessage newMessage;
	newMessage.vchMessage = vchMessage;
	newMessage.vchMessageFrom = vchFromString(strCipherTextFrom);
	newMessage.vchMessageTo = vchFromString(strCipherTextTo);
	newMessage.vchSubject = vchMySubject;
	newMessage.vchAliasFrom = aliasFrom.vchAlias;
	newMessage.vchAliasTo = aliasTo.vchAlias;
	newMessage.nHeight = chainActive.Tip()->nHeight;

	const vector<unsigned char> &data = newMessage.Serialize();
    uint256 hash = Hash(data.begin(), data.end());
 	
    vector<unsigned char> vchHashMessage = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_MESSAGE_ACTIVATE) << vchMessage << vchHashMessage << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

	// send the tranasction
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
	CreateFeeRecipient(scriptData, aliasFrom.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);
	
	
	
	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxAliasIn, aliasFrom.multiSigInfo.vchAliases.size() > 0);
	UniValue res(UniValue::VARR);
	if(aliasFrom.multiSigInfo.vchAliases.size() > 0)
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
			res.push_back(stringFromVch(vchMessage));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchMessage));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchMessage));
	}
	return res;
}

UniValue messageinfo(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("messageinfo <guid>\n"
                "Show stored values of a single message.\n");

    vector<unsigned char> vchMessage = vchFromValue(params[0]);

    // look for a transaction with this key, also returns
    // an message UniValue if it is found
    CTransaction tx;

	vector<CMessage> vtxPos;

    UniValue oMessage(UniValue::VOBJ);
    vector<unsigned char> vchValue;

	if (!pmessagedb->ReadMessage(vchMessage, vtxPos) || vtxPos.empty())
		 throw runtime_error("failed to read from message DB");
	const CMessage &message = vtxPos.back();
	if(!BuildMessageJson(message, oMessage))
		throw runtime_error("Could not find this message");
    return oMessage;
}

UniValue messagereceivelist(const UniValue& params, bool fHelp) {
    if (fHelp || 2 < params.size())
        throw runtime_error("messagereceivelist [\"alias\",...] [<message>]\n"
                "list received messages that an array of aliases own");
	UniValue aliasesValue(UniValue::VARR);
	vector<string> aliases;
	if(params.size() >= 1)
	{
		if(params[0].isArray())
		{
			aliasesValue = params[0].get_array();
			for(unsigned int aliasIndex =0;aliasIndex<aliasesValue.size();aliasIndex++)
			{
				string lowerStr = aliasesValue[aliasIndex].get_str();
				boost::algorithm::to_lower(lowerStr);
				aliases.push_back(lowerStr);
			}
		}
		else
		{
			string aliasName =  params[0].get_str();
			boost::algorithm::to_lower(aliasName);
			if(aliasName != "")
				aliases.push_back(aliasName);
		}
	}
	vector<unsigned char> vchNameUniq;
    if (params.size() == 2)
        vchNameUniq = vchFromValue(params[1]);
	UniValue oRes(UniValue::VARR);
	map< vector<unsigned char>, int > vNamesI;
	vector<CMessage > messageScan;
	if(aliases.size() > 0)
	{
		if (!pmessagedb->ScanRecvMessages(vchNameUniq, aliases, 1000, messageScan))
			throw runtime_error("scan failed");
	}
	BOOST_FOREACH(const CMessage &message, messageScan) {
		// build the output
		UniValue oName(UniValue::VOBJ);
		BuildMessageJson(message, oName);
		oRes.push_back(oName);
	}
	

    return oRes;
}
bool BuildMessageJson(const CMessage& message, UniValue& oName)
{
	oName.push_back(Pair("GUID", stringFromVch(message.vchMessage)));
	string sTime;
	CBlockIndex *pindex = chainActive[message.nHeight];
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	string strAddress = "";
	oName.push_back(Pair("time", sTime));
	CAliasIndex aliasFrom, aliasTo;
	CTransaction aliastxtmp;
	bool isExpired = false;
	vector<CAliasIndex> aliasVtxPos;
	if(GetTxAndVtxOfAlias(message.vchAliasFrom, aliasFrom, aliastxtmp, aliasVtxPos, isExpired, true))
	{
		aliasFrom.nHeight = message.nHeight;
		aliasFrom.GetAliasFromList(aliasVtxPos);
	}
	else
		return false;
	aliasVtxPos.clear();
	if(GetTxAndVtxOfAlias(message.vchAliasTo, aliasTo, aliastxtmp, aliasVtxPos, isExpired, true))
	{
		aliasTo.nHeight = message.nHeight;
		aliasTo.GetAliasFromList(aliasVtxPos);
	}
	else
		return false;
	oName.push_back(Pair("from", stringFromVch(message.vchAliasFrom)));
	oName.push_back(Pair("to", stringFromVch(message.vchAliasTo)));

	oName.push_back(Pair("subject", stringFromVch(message.vchSubject)));
	string strDecrypted = "";
	string strData = _("Encrypted for recipient of message");
	if(DecryptMessage(aliasTo.vchPubKey, message.vchMessageTo, strDecrypted))
		strData = strDecrypted;
	else if(DecryptMessage(aliasFrom.vchPubKey, message.vchMessageFrom, strDecrypted))
		strData = strDecrypted;
	oName.push_back(Pair("message", strData));
	return true;
}

UniValue messagesentlist(const UniValue& params, bool fHelp) {
    if (fHelp || 2 < params.size())
        throw runtime_error("messagesentlist [\"alias\",...] [<message>]\n"
                "list sent messages that an array of aliases own");
	UniValue aliasesValue(UniValue::VARR);
	vector<string> aliases;
	if(params.size() >= 1)
	{
		if(params[0].isArray())
		{
			aliasesValue = params[0].get_array();
			for(unsigned int aliasIndex =0;aliasIndex<aliasesValue.size();aliasIndex++)
			{
				string lowerStr = aliasesValue[aliasIndex].get_str();
				boost::algorithm::to_lower(lowerStr);
				aliases.push_back(lowerStr);
			}
		}
		else
		{
			string aliasName =  params[0].get_str();
			boost::algorithm::to_lower(aliasName);
			if(aliasName != "")
				aliases.push_back(aliasName);
		}
	}
	vector<unsigned char> vchNameUniq;
    if (params.size() == 2)
        vchNameUniq = vchFromValue(params[1]);
	UniValue oRes(UniValue::VARR);
	map< vector<unsigned char>, int > vNamesI;
	vector<CMessage> messageScan;
	if(aliases.size() > 0)
	{
		for(unsigned int aliasIndex =0;aliasIndex<aliases.size();aliasIndex++)
		{
			string name = aliases[aliasIndex];
			vector<unsigned char> vchAlias = vchFromString(name);
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

			CTransaction tx;

			vector<unsigned char> vchValue;
			BOOST_FOREACH(const CAliasIndex &theAlias, vtxPos)
			{
				if(!GetSyscoinTransaction(theAlias.nHeight, theAlias.txHash, tx, Params().GetConsensus()))
					continue;

				CMessage message(tx);
				if(!message.IsNull() && message.vchAliasFrom == vchAlias)
				{
					if (vNamesI.find(message.vchMessage) != vNamesI.end())
						continue;
					if (vchNameUniq.size() > 0 && vchNameUniq != message.vchMessage)
						continue;
					messageScan.push_back(message);
					vNamesI[message.vchMessage] = message.nHeight;
				}
			}
		}
	}
	BOOST_FOREACH(const CMessage &message, messageScan) {
		// build the output
		UniValue oName(UniValue::VOBJ);
		BuildMessageJson(message, oName);
		oRes.push_back(oName);
	}
    return oRes;
}

void MessageTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry)
{
	string opName = messageFromOp(op);
	CMessage message;
	if(!message.UnserializeFromData(vchData, vchHash))
		return;

	bool isExpired = false;
	vector<CAliasIndex> aliasVtxPosFrom;
	vector<CAliasIndex> aliasVtxPosTo;
	CTransaction aliastx;
	CAliasIndex dbAliasFrom, dbAliasTo;
	if(GetTxAndVtxOfAlias(message.vchAliasFrom, dbAliasFrom, aliastx, aliasVtxPosFrom, isExpired, true))
	{
		dbAliasFrom.nHeight = message.nHeight;
		dbAliasFrom.GetAliasFromList(aliasVtxPosFrom);
	}
	if(GetTxAndVtxOfAlias(message.vchAliasTo, dbAliasTo, aliastx, aliasVtxPosTo, isExpired, true))
	{
		dbAliasTo.nHeight = message.nHeight;
		dbAliasTo.GetAliasFromList(aliasVtxPosTo);
	}
	entry.push_back(Pair("txtype", opName));
	entry.push_back(Pair("GUID", stringFromVch(message.vchMessage)));

	string aliasFromValue = stringFromVch(message.vchAliasFrom);
	entry.push_back(Pair("from", aliasFromValue));

	string aliasToValue = stringFromVch(message.vchAliasTo);
	entry.push_back(Pair("to", aliasToValue));

	string subjectValue = stringFromVch(message.vchSubject);
	entry.push_back(Pair("subject", subjectValue));

	string strMessage =_("Encrypted for recipient of message");
	string strDecrypted = "";
	if(DecryptMessage(dbAliasTo.vchPubKey, message.vchMessageTo, strDecrypted))
		strMessage = strDecrypted;
	else if(DecryptMessage(dbAliasFrom.vchPubKey, message.vchMessageFrom, strDecrypted))
		strMessage = strDecrypted;	

	entry.push_back(Pair("message", strMessage));


}
