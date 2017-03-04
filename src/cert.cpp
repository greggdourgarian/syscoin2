#include "cert.h"
#include "alias.h"
#include "offer.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "base58.h"
#include "core_io.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "chainparams.h"
#include "messagecrypter.h"
#include "coincontrol.h"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/range/adaptor/reversed.hpp>
using namespace std;
extern void SendMoneySyscoin(const vector<unsigned char> &vchAlias, const CRecipient &aliasRecipient, const CRecipient &aliasPaymentRecipient, vector<CRecipient> &vecSend, CWalletTx& wtxNew, CCoinControl* coinControl, bool useOnlyAliasPaymentToFund=false, bool transferAlias=false);
bool EncryptMessage(const vector<unsigned char> &vchPubKey, const string &strMessage, string &strCipherText)
{
	strCipherText.clear();
	CMessageCrypter crypter;
	if(!crypter.Encrypt(stringFromVch(vchPubKey), strMessage, strCipherText))
		return false;
	return true;
}
bool DecryptPrivateKey(const vector<unsigned char> &vchPubKey, const vector<unsigned char> &vchCipherText, string &strMessage)
{
	strMessage.clear();
	std::vector<unsigned char> vchPrivateKey;
	CMessageCrypter crypter;

	CKey PrivateKey;
	CPubKey PubKey(vchPubKey);
	CKeyID pubKeyID = PubKey.GetID();
	if (!pwalletMain->GetKey(pubKeyID, PrivateKey))
		return false;
	CSyscoinSecret Secret(PrivateKey);
	PrivateKey = Secret.GetKey();
	vchPrivateKey = std::vector<unsigned char>(PrivateKey.begin(), PrivateKey.end());
	strMessage.clear();
	if(!crypter.Decrypt(stringFromVch(vchPrivateKey), stringFromVch(vchCipherText), strMessage))
		return false;
	
	
	return true;
}
bool DecryptPrivateKey(const CAliasIndex& alias, string &strKey)
{
	strKey.clear();
	if(DecryptPrivateKey(alias.vchPubKey, alias.vchEncryptionPrivateKey, strKey))
		return !strKey.empty();
	return !strKey.empty();
}
bool DecryptMessage(const CAliasIndex& alias, const vector<unsigned char> &vchCipherText, string &strMessage)
{
	strMessage.clear();
	// get private key from alias or use one passed in to get the encryption private key
	string strKey;
	if(!DecryptPrivateKey(alias, strKey))
		return false;
	// use encryption private key to get data
	CMessageCrypter crypter;
	if(!crypter.Decrypt(strKey, stringFromVch(vchCipherText), strMessage))
		return false;
	return true;
}
void PutToCertList(std::vector<CCert> &certList, CCert& index) {
	int i = certList.size() - 1;
	BOOST_REVERSE_FOREACH(CCert &o, certList) {
        if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	certList[i] = index;
            return;
        }
        i--;
	}
    certList.push_back(index);
}
bool IsCertOp(int op) {
    return op == OP_CERT_ACTIVATE
        || op == OP_CERT_UPDATE
        || op == OP_CERT_TRANSFER;
}

uint64_t GetCertExpiration(const CCert& cert) {
	uint64_t nTime = chainActive.Tip()->nTime + 1;
	CAliasUnprunable aliasUnprunable;
	if (paliasdb && paliasdb->ReadAliasUnprunable(cert.vchAlias, aliasUnprunable) && !aliasUnprunable.IsNull())
		nTime = aliasUnprunable.nExpireTime;
	
	return nTime;
}


string certFromOp(int op) {
    switch (op) {
    case OP_CERT_ACTIVATE:
        return "certactivate";
    case OP_CERT_UPDATE:
        return "certupdate";
    case OP_CERT_TRANSFER:
        return "certtransfer";
    default:
        return "<unknown cert op>";
    }
}
bool CCert::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsCert(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsCert >> *this;

		vector<unsigned char> vchCertData;
		Serialize(vchCertData);
		const uint256 &calculatedHash = Hash(vchCertData.begin(), vchCertData.end());
		const vector<unsigned char> &vchRandCert = vchFromValue(calculatedHash.GetHex());
		if(vchRandCert != vchHash)
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
bool CCert::UnserializeFromTx(const CTransaction &tx) {
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
void CCert::Serialize( vector<unsigned char> &vchData) {
    CDataStream dsCert(SER_NETWORK, PROTOCOL_VERSION);
    dsCert << *this;
	vchData = vector<unsigned char>(dsCert.begin(), dsCert.end());

}
bool CCertDB::CleanupDatabase(int &servicesCleaned)
{
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->SeekToFirst();
	vector<CCert> vtxPos;
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "certi") {
            	const vector<unsigned char> &vchMyCert= key.second;         
				pcursor->GetValue(vtxPos);	
				if (vtxPos.empty()){
					servicesCleaned++;
					EraseCert(vchMyCert);
					pcursor->Next();
					continue;
				}
				const CCert &txPos = vtxPos.back();
  				if (chainActive.Tip()->nTime >= GetCertExpiration(txPos))
				{
					servicesCleaned++;
					EraseCert(vchMyCert);
				} 
				
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
	return true;
}
bool CCertDB::GetDBCerts(std::vector<CCert>& certs, const uint64_t &nExpireFilter, const std::vector<std::string>& aliasArray)
{
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->SeekToFirst();
	vector<CCert> vtxPos;
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "certi") {       
				pcursor->GetValue(vtxPos);	
				if (vtxPos.empty())
				{
					pcursor->Next();
					continue;
				}
				const CCert &txPos = vtxPos.back();
				if(chainActive.Height() <= txPos.nHeight || chainActive[txPos.nHeight]->nTime < nExpireFilter)
				{
					pcursor->Next();
					continue;
				}
  				if (chainActive.Tip()->nTime >= GetCertExpiration(txPos))
				{
					pcursor->Next();
					continue;
				}
				if(aliasArray.size() > 0)
				{
					if (std::find(aliasArray.begin(), aliasArray.end(), stringFromVch(txPos.vchAlias)) == aliasArray.end())
					{
						pcursor->Next();
						continue;
					}
				}
				certs.push_back(txPos);	
            }
			
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
	return true;
}
int IndexOfCertOutput(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return -1;
    vector<vector<unsigned char> > vvch;
	int op;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeCertScript(out.scriptPubKey, op, vvch)) {
			return i;
		}
	}
	return -1;
}

bool GetTxOfCert(const vector<unsigned char> &vchCert,
        CCert& txPos, CTransaction& tx, bool skipExpiresCheck) {
    vector<CCert> vtxPos;
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetCertExpiration(txPos)) {
        string cert = stringFromVch(vchCert);
        LogPrintf("GetTxOfCert(%s) : expired", cert.c_str());
        return false;
    }

    if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfCert() : could not read tx from disk");

    return true;
}

bool GetTxAndVtxOfCert(const vector<unsigned char> &vchCert,
        CCert& txPos, CTransaction& tx,  vector<CCert> &vtxPos, bool skipExpiresCheck) {
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetCertExpiration(txPos)) {
        string cert = stringFromVch(vchCert);
        LogPrintf("GetTxOfCert(%s) : expired", cert.c_str());
        return false;
    }

    if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfCert() : could not read tx from disk");

    return true;
}
bool GetVtxOfCert(const vector<unsigned char> &vchCert,
        CCert& txPos, vector<CCert> &vtxPos, bool skipExpiresCheck) {
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetCertExpiration(txPos)) {
        string cert = stringFromVch(vchCert);
        LogPrintf("GetTxOfCert(%s) : expired", cert.c_str());
        return false;
    }

    return true;
}
bool DecodeAndParseCertTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CCert cert;
	bool decode = DecodeCertTx(tx, op, nOut, vvch);
	bool parse = cert.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeCertTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeCertScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
    if (!found) vvch.clear();
    return found;
}


bool DecodeCertScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
    opcodetype opcode;
	vvch.clear();
    if (!script.GetOp(pc, opcode)) return false;
    if (opcode < OP_1 || opcode > OP_16) return false;
    op = CScript::DecodeOP_N(opcode);

	bool found = false;
	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP)
		{
			found = true;
			break;
		}
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;
	return found && IsCertOp(op);
}
bool DecodeCertScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeCertScript(script, op, vvch, pc);
}
bool RemoveCertScriptPrefix(const CScript& scriptIn, CScript& scriptOut) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeCertScript(scriptIn, op, vvch, pc))
		return false;
	scriptOut = CScript(pc, scriptIn.end());
	return true;
}

bool CheckCertInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs,
        const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, bool dontaddtodb) {
	if (tx.IsCoinBase() && !fJustCheck && !dontaddtodb)
	{
		LogPrintf("*Trying to add cert in coinbase transaction, skipping...");
		return true;
	}
	if (fDebug)
		LogPrintf("*** CERT %d %d %s %s\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			fJustCheck ? "JUSTCHECK" : "BLOCK");
	bool foundAlias = false;
    const COutPoint *prevOutput = NULL;
    const CCoins *prevCoins;

	int prevAliasOp = 0;
    // Make sure cert outputs are not spent by a regular transaction, or the cert would be lost
	if (tx.nVersion != SYSCOIN_TX_VERSION) 
	{
		errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2000 - " + _("Non-Syscoin transaction found");
		return true;
	}
	vector<vector<unsigned char> > vvchPrevAliasArgs;
	// unserialize cert from txn, check for valid
	CCert theCert;
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	int nDataOut;
	if(!GetSyscoinData(tx, vchData, vchHash, nDataOut) || !theCert.UnserializeFromData(vchData, vchHash))
	{
		errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR ERRCODE: 2001 - " + _("Cannot unserialize data inside of this transaction relating to a certificate");
		return true;
	}

	if(fJustCheck)
	{
		if(vvchArgs.size() != 2)
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2002 - " + _("Certificate arguments incorrect size");
			return error(errorMessage.c_str());
		}

					
		if(vvchArgs.size() <= 1 || vchHash != vvchArgs[1])
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2003 - " + _("Hash provided doesn't match the calculated hash of the data");
			return true;
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


	
	CAliasIndex alias;
	CTransaction aliasTx;
	vector<CCert> vtxPos;
	string retError = "";
	if(fJustCheck)
	{
		if (vvchArgs.empty() ||  vvchArgs[0].size() > MAX_GUID_LENGTH)
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2004 - " + _("Certificate hex guid too long");
			return error(errorMessage.c_str());
		}
		if(theCert.vchData.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2006 - " + _("Certificate private data too big");
			return error(errorMessage.c_str());
		}
		if(theCert.vchEncryptionPrivateKey.size() > MAX_ENCRYPTED_GUID_LENGTH)
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 3006 - " + _("Encryption private to key too long");
			return error(errorMessage.c_str());
		if(theCert.vchEncryptionPublicKey.size() > MAX_GUID_LENGTH)
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 3006 - " + _("Encryption public key too long");
			return error(errorMessage.c_str());
		}
		if(theCert.vchPubData.size() > MAX_VALUE_LENGTH)
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2007 - " + _("Certificate public data too big");
			return error(errorMessage.c_str());
		}
		if(!theCert.vchCert.empty() && theCert.vchCert != vvchArgs[0])
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2008 - " + _("Guid in data output doesn't match guid in transaction");
			return error(errorMessage.c_str());
		}
		switch (op) {
		case OP_CERT_ACTIVATE:
			if (theCert.vchCert != vvchArgs[0])
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2009 - " + _("Certificate guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!theCert.vchLinkAlias.empty())
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2010 - " + _("Certificate linked alias not allowed in activate");
				return error(errorMessage.c_str());
			}
			if(!IsAliasOp(prevAliasOp) || vvchPrevAliasArgs.empty() || theCert.vchAlias != vvchPrevAliasArgs[0])
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2011 - " + _("Alias input mismatch");
				return error(errorMessage.c_str());
			}
			break;

		case OP_CERT_UPDATE:
			if (theCert.vchCert != vvchArgs[0])
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2014 - " + _("Certificate guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!IsAliasOp(prevAliasOp) || vvchPrevAliasArgs.empty() || theCert.vchAlias != vvchPrevAliasArgs[0])
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2016 - " + _("Alias input mismatch");
				return error(errorMessage.c_str());
			}
			break;

		case OP_CERT_TRANSFER:
			if (theCert.vchCert != vvchArgs[0])
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2018 - " + _("Certificate guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!IsAliasOp(prevAliasOp) || vvchPrevAliasArgs.empty() || theCert.vchAlias != vvchPrevAliasArgs[0])
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2019 - " + _("Alias input mismatch");
				return error(errorMessage.c_str());
			}
			break;

		default:
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2021 - " + _("Certificate transaction has unknown op");
			return error(errorMessage.c_str());
		}
	}

    if (!fJustCheck ) {
		if(op != OP_CERT_ACTIVATE) 
		{
			// if not an certnew, load the cert data from the DB
			CCert dbCert;
			if(!GetVtxOfCert(vvchArgs[0], dbCert, vtxPos))	
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2022 - " + _("Failed to read from certificate DB");
				return true;
			}
			if(theCert.vchData.empty())
				theCert.vchData = dbCert.vchData;
			if(theCert.vchPubData.empty())
				theCert.vchPubData = dbCert.vchPubData;
			if(theCert.vchEncryptionPrivateKey.empty())
				theCert.vchEncryptionPrivateKey = dbCert.vchEncryptionPrivateKey;
			if(theCert.vchEncryptionPublicKey.empty())
				theCert.vchEncryptionPublicKey = dbCert.vchEncryptionPublicKey;
			
			// user can't update safety level after creation
			theCert.safetyLevel = dbCert.safetyLevel;
			theCert.vchCert = dbCert.vchCert;
			if(theCert.vchAlias != dbCert.vchAlias)
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2023 - " + _("Wrong alias input provided in this certificate transaction");
				theCert.vchAlias = dbCert.vchAlias;
			}
			if(op == OP_CERT_TRANSFER)
			{
				vector<CAliasIndex> vtxAlias;
				bool isExpired = false;
				// check toalias
				if(!GetVtxOfAlias(theCert.vchLinkAlias, alias, vtxAlias, isExpired))
				{
					errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2024 - " + _("Cannot find alias you are transferring to. It may be expired");		
				}
				else
				{
					theCert.vchAlias = theCert.vchLinkAlias;		
					if(!alias.acceptCertTransfers)
					{
						errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2025 - " + _("The alias you are transferring to does not accept certificate transfers");
						theCert = dbCert;	
					}
				}
			}
			else
			{
				theCert.bTransferViewOnly = dbCert.bTransferViewOnly;
			}
			theCert.vchLinkAlias.clear();
			if(dbCert.bTransferViewOnly)
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2026 - " + _("Cannot edit or transfer this certificate. It is view-only.");
				theCert = dbCert;
			}
		}
		else
		{
			if (pcertdb->ExistsCert(vvchArgs[0]))
			{
				errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2027 - " + _("Certificate already exists");
				return true;
			}
		}
        // set the cert's txn-dependent values
		theCert.nHeight = nHeight;
		theCert.txHash = tx.GetHash();
		PutToCertList(vtxPos, theCert);
        // write cert  

        if (!dontaddtodb && !pcertdb->WriteCert(vvchArgs[0], vtxPos))
		{
			errorMessage = "SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2028 - " + _("Failed to write to certifcate DB");
            return error(errorMessage.c_str());
		}
		

      			
        // debug
		if(fDebug)
			LogPrintf( "CONNECTED CERT: op=%s cert=%s hash=%s height=%d\n",
                certFromOp(op).c_str(),
                stringFromVch(vvchArgs[0]).c_str(),
                tx.GetHash().ToString().c_str(),
                nHeight);
    }
    return true;
}





UniValue certnew(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
		"certnew <alias> <public> [private] [encryption_publickey] [encryption_privatekey]\n"
						"<alias> An alias you own.\n"
                        "<public> public data, 256 characters max.\n"
						"<private> private data, 256 characters max.\n"
						"<encryption_publickey> Encryption public key. Certificate private data is encrypted to this key, anyone who has access to private key can read message.\n"	
						"<encryption_privatekey> Encrypted private key to alias used for encryption/decryption of this message. Should be encrypted to encryption_publickey of alias.\n"	
						+ HelpRequiringPassphrase());
	vector<unsigned char> vchAlias = vchFromValue(params[0]);
    
	vector<unsigned char> vchPubData = vchFromString(params[1].get_str());

	string strEncryptionPublicKey = "";
	string strEncryptionPrivateKey = "";
	string strData = "";
	if(CheckParam(params, 2))
		strData = params[2].get_str();
	if(CheckParam(params, 3))
		strEncryptionPublicKey = params[3].get_str();
	if(CheckParam(params, 4))
		strEncryptionPrivateKey = params[4].get_str();

	// check for alias existence in DB
	CTransaction aliastx;
	CAliasIndex theAlias;

	if (!GetTxOfAlias(vchAlias, theAlias, aliastx))
		throw runtime_error("SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2500 - " + _("failed to read alias from alias DB"));

	
    // gather inputs
	vector<unsigned char> vchCert = vchFromString(GenerateSyscoinGuid());
    // this is a syscoin transaction
    CWalletTx wtx;

    CScript scriptPubKeyOrig;
	CSyscoinAddress aliasAddress;
	GetAddress(theAlias, &aliasAddress, scriptPubKeyOrig);


    CScript scriptPubKey,scriptPubKeyAlias;

	// calculate net
    // build cert object
    CCert newCert;
	newCert.vchCert = vchCert;
	if(!strData.empty())
		newCert.vchData = ParseHex(strData);
	newCert.vchPubData = vchPubData;
	if(!strEncryptionPublicKey.empty())
		newCert.vchEncryptionPublicKey = ParseHex(strEncryptionPublicKey);
	if(!strEncryptionPrivateKey.empty())
		newCert.vchEncryptionPrivateKey = ParseHex(strEncryptionPrivateKey);
	newCert.nHeight = chainActive.Tip()->nHeight;
	newCert.vchAlias = vchAlias;
	newCert.safetyLevel = 0;

	vector<unsigned char> data;
	newCert.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
 	
    vector<unsigned char> vchHashCert = vchFromValue(hash.GetHex());

    scriptPubKey << CScript::EncodeOP_N(OP_CERT_ACTIVATE) << vchCert << vchHashCert << OP_2DROP << OP_DROP;
    scriptPubKey += scriptPubKeyOrig;
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << theAlias.vchAlias << theAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;

	// use the script pub key to create the vecsend which sendmoney takes and puts it into vout
	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	CRecipient aliasPaymentRecipient;
	CreateAliasRecipient(scriptPubKeyOrig, theAlias.vchAlias, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, aliasPaymentRecipient);
		
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);

	
	
	CCoinControl coinControl;
	coinControl.fAllowOtherInputs = false;
	coinControl.fAllowWatchOnly = false;	
	SendMoneySyscoin(vchAlias, aliasRecipient, aliasPaymentRecipient, vecSend, wtx, &coinControl);
	UniValue res(UniValue::VARR);
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
		res.push_back(stringFromVch(vchCert));
	}
	else
	{
		res.push_back(hex_str);
		res.push_back(stringFromVch(vchCert));
		res.push_back("false");
	}
	return res;
}

UniValue certupdate(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 1 || params.size() > 5)
        throw runtime_error(
		"certupdate <guid> [public] [private] [encryption_publickey] [encryption_privatekey]\n"
						"Perform an update on an certificate you control.\n"
						"<guid> certificate guidkey.\n"
                        "<public> public data, 256 characters max.\n"
						"<private> private data, 256 characters max.\n"
						"<encryption_publickey> Encryption public key. Certificate private data is encrypted to this key, anyone who has access to private key can read message.\n"	
						"<encryption_privatekey> Encrypted private key to alias used for encryption/decryption of this message. Should be encrypted to encryption_publickey of alias.\n"	
						+ HelpRequiringPassphrase());
	vector<unsigned char> vchCert = vchFromValue(params[0]);

	string strEncryptionPublicKey = "";
	string strEncryptionPrivateKey = "";
	string strData = "";
	string strPubData = "";
	if(CheckParam(params, 1))
		strPubData = params[1].get_str();
	if(CheckParam(params, 2))
		strData = params[2].get_str();
	if(CheckParam(params, 3))
		strEncryptionPublicKey = params[3].get_str();
	if(CheckParam(params, 4))
		strEncryptionPrivateKey = params[4].get_str();



    // this is a syscoind txn
    CWalletTx wtx;
    CScript scriptPubKeyOrig;


    // look for a transaction with this key
    CTransaction tx;
	CCert theCert;
	
    if (!GetTxOfCert( vchCert, theCert, tx))
        throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR: ERRCODE: 2504 - " + _("Could not find a certificate with this key"));

	CTransaction aliastx;
	CAliasIndex theAlias;

	if (!GetTxOfAlias(theCert.vchAlias, theAlias, aliastx))
		throw runtime_error("SYSCOIN_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2505 - " + _("Failed to read alias from alias DB"));

	CCert copyCert = theCert;
	theCert.ClearCert();
	CSyscoinAddress aliasAddress;
	GetAddress(theAlias, &aliasAddress, scriptPubKeyOrig);

    // create CERTUPDATE txn keys
    CScript scriptPubKey;

	if(!strData.empty())
		theCert.vchData = ParseHex(strData);
	if(!strPubData.empty())
		theCert.vchPubData = vchFromString(strPubData);
	if(!strEncryptionPublicKey.empty())
		theCert.vchEncryptionPublicKey = ParseHex(strEncryptionPublicKey);
	if(!strEncryptionPrivateKey.empty())
		theCert.vchEncryptionPrivateKey = ParseHex(strEncryptionPrivateKey);

	theCert.vchAlias = theAlias.vchAlias;
	theCert.nHeight = chainActive.Tip()->nHeight;
	vector<unsigned char> data;
	theCert.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
 	
    vector<unsigned char> vchHashCert = vchFromValue(hash.GetHex());
    scriptPubKey << CScript::EncodeOP_N(OP_CERT_UPDATE) << vchCert << vchHashCert << OP_2DROP << OP_DROP;
    scriptPubKey += scriptPubKeyOrig;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CScript scriptPubKeyAlias;
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << theAlias.vchAlias << theAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyOrig;
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	CRecipient aliasPaymentRecipient;
	CreateAliasRecipient(scriptPubKeyOrig, theAlias.vchAlias, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, aliasPaymentRecipient);
		
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);
	
	
	CCoinControl coinControl;
	coinControl.fAllowOtherInputs = false;
	coinControl.fAllowWatchOnly = false;	
	SendMoneySyscoin(theAlias.vchAlias, aliasRecipient, aliasPaymentRecipient, vecSend, wtx, &coinControl);	
 	UniValue res(UniValue::VARR);

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
		res.push_back(wtx.GetHash().GetHex());
	else
	{
		res.push_back(hex_str);
		res.push_back("false");
	}
	return res;
}


UniValue certtransfer(const UniValue& params, bool fHelp) {
 if (fHelp || params.size() < 2 || params.size() > 7)
        throw runtime_error(
		"certtransfer <guid> <alias> [public] [private] [encryption_publickey] [encryption_privatekey] [viewonly=No]\n"
						"Transfer a certificate you own to another alias.\n"
						"<guid> certificate guidkey.\n"
						"<alias> alias to transfer to.\n"
                        "<public> public data, 256 characters max.\n"
						"<private> private data, 256 characters max.\n"
						"<encryption_publickey> Encryption public key. Certificate private data is encrypted to this key, anyone who has access to private key can read message.\n"	
						"<encryption_privatekey> Encrypted private key to alias used for encryption/decryption of this message. Should be encrypted to encryption_publickey of alias.\n"					
						"<viewonly> Transfer the certificate as view-only. Recipient cannot edit, transfer or sell this certificate in the future.\n"
						+ HelpRequiringPassphrase());

    // gather & validate inputs
	vector<unsigned char> vchCert = vchFromValue(params[0]);
	vector<unsigned char> vchAlias = vchFromValue(params[1]);

	string strEncryptionPublicKey = "";
	string strEncryptionPrivateKey = "";
	string strData = "";
	string strPubData = "";
	string strViewOnly = "No";
	if(CheckParam(params, 2))
		strPubData = params[2].get_str();
	if(CheckParam(params, 3))
		strData = params[3].get_str();
	if(CheckParam(params, 4))
		strEncryptionPublicKey = params[4].get_str();
	if(CheckParam(params, 5))
		strEncryptionPrivateKey = params[5].get_str();
	if(CheckParam(params, 6))
		strViewOnly = params[6].get_str();


	if(CheckParam(params, 3))
		strViewOnly = params[3].get_str();
	// check for alias existence in DB
	CTransaction tx;
	CAliasIndex toAlias;
	if (!GetTxOfAlias(vchAlias, toAlias, tx))
		throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR: ERRCODE: 2509 - " + _("Failed to read transfer alias from DB"));

    // this is a syscoin txn
    CWalletTx wtx;
    CScript scriptPubKeyOrig, scriptPubKeyFromOrig;

    CTransaction aliastx;
	CCert theCert;
    if (!GetTxOfCert( vchCert, theCert, tx))
        throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR: ERRCODE: 2510 - " + _("Could not find a certificate with this key"));

	CAliasIndex fromAlias;
	if(!GetTxOfAlias(theCert.vchAlias, fromAlias, aliastx))
	{
		 throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR: ERRCODE: 2511 - " + _("Could not find the certificate alias"));
	}

	CSyscoinAddress sendAddr;
	GetAddress(toAlias, &sendAddr, scriptPubKeyOrig);
	CSyscoinAddress fromAddr;
	GetAddress(fromAlias, &fromAddr, scriptPubKeyFromOrig);

	CCert copyCert = theCert;
	theCert.ClearCert();
    CScript scriptPubKey;
	theCert.nHeight = chainActive.Tip()->nHeight;
	theCert.vchAlias = fromAlias.vchAlias;
	theCert.vchLinkAlias = toAlias.vchAlias;
	theCert.safetyLevel = copyCert.safetyLevel;

	if(!strData.empty())
		theCert.vchData = ParseHex(strData);
	if(!strPubData.empty())
		theCert.vchPubData = vchFromString(strPubData);
	if(!strEncryptionPublicKey.empty())
		theCert.vchEncryptionPublicKey = ParseHex(strEncryptionPublicKey);
	if(!strEncryptionPrivateKey.empty())
		theCert.vchEncryptionPrivateKey = ParseHex(strEncryptionPrivateKey);


	if(strViewOnly.empty())
		theCert.bTransferViewOnly = copyCert.bTransferViewOnly;
	else
		theCert.bTransferViewOnly = strViewOnly == "Yes"? true:false;

	vector<unsigned char> data;
	theCert.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
 	
    vector<unsigned char> vchHashCert = vchFromValue(hash.GetHex());
    scriptPubKey << CScript::EncodeOP_N(OP_CERT_TRANSFER) << vchCert << vchHashCert << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
    // send the cert pay txn
	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);

	CScript scriptPubKeyAlias;
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << fromAlias.vchAlias << fromAlias.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyAlias += scriptPubKeyFromOrig;
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	CRecipient aliasPaymentRecipient;
	CreateAliasRecipient(scriptPubKeyFromOrig, fromAlias.vchAlias, fromAlias.vchAliasPeg, chainActive.Tip()->nHeight, aliasPaymentRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, fromAlias.vchAliasPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);
	
	
	CCoinControl coinControl;
	coinControl.fAllowOtherInputs = false;
	coinControl.fAllowWatchOnly = false;
	SendMoneySyscoin(fromAlias.vchAlias, aliasRecipient, aliasPaymentRecipient, vecSend, wtx, &coinControl);
	UniValue res(UniValue::VARR);

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
		res.push_back(wtx.GetHash().GetHex());
	else
	{
		res.push_back(hex_str);
		res.push_back("false");
	}
	return res;
}


UniValue certinfo(const UniValue& params, bool fHelp) {
    if (fHelp || 1 < params.size() || 2 < params.size())
        throw runtime_error("certinfo <guid> [walletless=No]\n"
                "Show stored values of a single certificate and its .\n");

    vector<unsigned char> vchCert = vchFromValue(params[0]);

	string strWalletless = "No";
	if(params.size() >= 2)
		strWalletless = params[1].get_str();

	vector<CCert> vtxPos;

	UniValue oCert(UniValue::VOBJ);
    vector<unsigned char> vchValue;

	if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
		throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR: ERRCODE: 2515 - " + _("Failed to read from cert DB"));

	CAliasIndex alias;
	CTransaction aliastx;
	if (!GetTxOfAlias(vtxPos.back().vchAlias, alias, aliastx, true))
		throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR: ERRCODE: 2516 - " + _("Failed to read xfer alias from alias DB"));

	if(!BuildCertJson(vtxPos.back(), alias, oCert, strWalletless))
		oCert.clear();
    return oCert;
}

UniValue certlist(const UniValue& params, bool fHelp) {
    if (fHelp || 3 < params.size())
        throw runtime_error("certlist [\"alias\",...] [<cert>] [walletless=No]\n"
                "list certs that an array of aliases own. Set of aliases to look up based on alias.");
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
				if(!lowerStr.empty())
					aliases.push_back(lowerStr);
			}
		}
		else
		{
			string aliasName =  params[0].get_str();
			boost::algorithm::to_lower(aliasName);
			if(!aliasName.empty())
				aliases.push_back(aliasName);
		}
	}
	vector<unsigned char> vchNameUniq;
    if (params.size() >= 2 && !params[1].get_str().empty())
        vchNameUniq = vchFromValue(params[1]);

	string strWalletless = "No";
	if(params.size() >= 3)
		strWalletless = params[2].get_str();

	UniValue oRes(UniValue::VARR);
	map< vector<unsigned char>, int > vNamesI;
	map< vector<unsigned char>, UniValue > vNamesO;
	if(aliases.size() > 0)
	{
		for(unsigned int aliasIndex =0;aliasIndex<aliases.size();aliasIndex++)
		{
			const string &name = aliases[aliasIndex];
			const vector<unsigned char> &vchAlias = vchFromString(name);
			vector<CAliasIndex> vtxPos;
			if (!paliasdb->ReadAlias(vchAlias, vtxPos) || vtxPos.empty())
				continue;
			CTransaction tx;
			for(auto& it : boost::adaptors::reverse(vtxPos)) {
				const CAliasIndex& theAlias = it;
				if(!GetSyscoinTransaction(theAlias.nHeight, theAlias.txHash, tx, Params().GetConsensus()))
					continue;
				CCert cert(tx);
				if(!cert.IsNull())
				{
					if (vNamesI.find(cert.vchCert) != vNamesI.end() && (theAlias.nHeight <= vNamesI[cert.vchCert] || vNamesI[cert.vchCert] < 0))
						continue;
					if (vchNameUniq.size() > 0 && vchNameUniq != cert.vchCert)
						continue;
					vector<CCert> vtxCertPos;
					if (!pcertdb->ReadCert(cert.vchCert, vtxCertPos) || vtxCertPos.empty())
						continue;
					const CCert &theCert = vtxCertPos.back();
					if(theCert.vchAlias != theAlias.vchAlias)
						continue;
					
					UniValue oCert(UniValue::VOBJ);
					vNamesI[cert.vchCert] = theAlias.nHeight;
					if(BuildCertJson(theCert, theAlias, oCert, strWalletless))
					{
						oRes.push_back(oCert);
					}
				}	
			}
		}
	}
    return oRes;
}
bool BuildCertJson(const CCert& cert, const CAliasIndex& alias, UniValue& oCert, const string &strWalletless)
{
	if(cert.safetyLevel >= SAFETY_LEVEL2)
		return false;
	if(alias.safetyLevel >= SAFETY_LEVEL2)
		return false;
	string sHeight = strprintf("%llu", cert.nHeight);
    oCert.push_back(Pair("cert", stringFromVch(cert.vchCert)));
    oCert.push_back(Pair("txid", cert.txHash.GetHex()));
    oCert.push_back(Pair("height", sHeight));
	string strEncryptionPrivateKey = "";
	string strData = "";
	if(!cert.vchData.empty())
	{
		string strKey = "";
		string strDecrypted = "";
		if(strWalletless == "Yes")
			strEncryptionPrivateKey = HexStr(cert.vchEncryptionPrivateKey);
		else
		{
			if(DecryptMessage(alias, cert.vchEncryptionPrivateKey, strKey))
				strEncryptionPrivateKey = HexStr(strKey);	
		}
		if(strWalletless == "Yes")
			strData = HexStr(cert.vchData);
		else
		{
			CMessageCrypter crypter;
			if(!strEncryptionPrivateKey.empty())
			{
				if(crypter.Decrypt(stringFromVch(ParseHex(strEncryptionPrivateKey)), stringFromVch(cert.vchData), strDecrypted))
					strData = strDecrypted;
			}
		}
	}
	oCert.push_back(Pair("encryption_privatekey", strEncryptionPrivateKey));
	oCert.push_back(Pair("encryption_publickey", HexStr(cert.vchEncryptionPublicKey)));
    oCert.push_back(Pair("privatevalue", strData));
	oCert.push_back(Pair("publicvalue", stringFromVch(cert.vchPubData)));
	unsigned char safetyLevel = max(cert.safetyLevel, alias.safetyLevel );
	oCert.push_back(Pair("safetylevel", safetyLevel));

	oCert.push_back(Pair("alias", stringFromVch(cert.vchAlias)));
	oCert.push_back(Pair("transferviewonly", cert.bTransferViewOnly? "true": "false"));
	int64_t expired_time = GetCertExpiration(cert);
	bool expired = false;
    if(expired_time <= chainActive.Tip()->nTime)
	{
		expired = true;
	}  
	int64_t expires_in = expired_time - chainActive.Tip()->nTime;
	if(expires_in < -1)
		expires_in = -1;

	oCert.push_back(Pair("expires_in", expires_in));
	oCert.push_back(Pair("expires_on", expired_time));
	oCert.push_back(Pair("expired", expired));
	return true;
}

UniValue certhistory(const UniValue& params, bool fHelp) {
    if (fHelp || 1 < params.size() || 2 < params.size())
        throw runtime_error("certhistory <guid> [walletless=No]\n"
                 "List all stored values of an cert.\n");

    vector<unsigned char> vchCert = vchFromValue(params[0]);

	string strWalletless = "No";
	if(params.size() >= 2)
		strWalletless = params[1].get_str();

    UniValue oRes(UniValue::VARR);
 
    vector<CCert> vtxPos;
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
		throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR: ERRCODE: 2518 - " + _("Failed to read from cert DB"));

	vector<CAliasIndex> vtxAliasPos;
	if (!paliasdb->ReadAlias(vtxPos.back().vchAlias, vtxAliasPos) || vtxAliasPos.empty())
		throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR: ERRCODE: 2519 - " + _("Failed to read from alias DB"));
	
    CCert txPos2;
	CAliasIndex alias;
	CTransaction tx;
	vector<vector<unsigned char> > vvch;
	int op, nOut;
    BOOST_FOREACH(txPos2, vtxPos) {
		vector<CAliasIndex> vtxAliasPos;
		if(!paliasdb->ReadAlias(txPos2.vchAlias, vtxAliasPos) || vtxAliasPos.empty())
			continue;
		if (!GetSyscoinTransaction(txPos2.nHeight, txPos2.txHash, tx, Params().GetConsensus())) {
			continue;
		}
		if (!DecodeCertTx(tx, op, nOut, vvch) )
			continue;

		alias.nHeight = txPos2.nHeight;
		alias.GetAliasFromList(vtxAliasPos);

		UniValue oCert(UniValue::VOBJ);
		string opName = certFromOp(op);
		oCert.push_back(Pair("certtype", opName));
		if(BuildCertJson(txPos2, alias, oCert, strWalletless))
			oRes.push_back(oCert);
    }
    
    return oRes;
}
void CertTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry)
{
	string opName = certFromOp(op);
	CCert cert;
	if(!cert.UnserializeFromData(vchData, vchHash))
		return;

	bool isExpired = false;
	vector<CAliasIndex> aliasVtxPos;
	vector<CCert> certVtxPos;
	CTransaction certtx, aliastx;
	CCert dbCert;
	if(GetTxAndVtxOfCert(cert.vchCert, dbCert, certtx, certVtxPos, true))
	{
		dbCert.nHeight = cert.nHeight;
		dbCert.GetCertFromList(certVtxPos);
	}
	CAliasIndex dbAlias;
	if(GetTxAndVtxOfAlias(cert.vchAlias, dbAlias, aliastx, aliasVtxPos, isExpired, true))
	{
		dbAlias.nHeight = cert.nHeight;
		dbAlias.GetAliasFromList(aliasVtxPos);
	}
	string noDifferentStr = _("<No Difference Detected>");

	entry.push_back(Pair("txtype", opName));
	entry.push_back(Pair("cert", stringFromVch(cert.vchCert)));

	string dataValue = noDifferentStr;
	if(!cert.vchData.empty() && cert.vchData != dbCert.vchData)
		dataValue = HexStr(cert.vchData);

	entry.push_back(Pair("data", dataValue));

	string dataPubValue = noDifferentStr;
	if(!cert.vchPubData.empty() && cert.vchPubData != dbCert.vchPubData)
		dataPubValue = stringFromVch(cert.vchPubData);

	entry.push_back(Pair("pubdata", dataPubValue));

	string aliasValue = noDifferentStr;
	if(!cert.vchLinkAlias.empty() && cert.vchLinkAlias != dbCert.vchAlias)
		aliasValue = stringFromVch(cert.vchLinkAlias);
	if(cert.vchAlias != dbCert.vchAlias)
		aliasValue = stringFromVch(cert.vchAlias);

	entry.push_back(Pair("alias", aliasValue));


	string transferViewOnlyValue = noDifferentStr;
	if(cert.bTransferViewOnly != dbCert.bTransferViewOnly)
		transferViewOnlyValue = cert.bTransferViewOnly? "Yes": "No";

	entry.push_back(Pair("transferviewonly", transferViewOnlyValue));


	string safetyLevelValue = noDifferentStr;
	if(cert.safetyLevel != dbCert.safetyLevel)
		safetyLevelValue = cert.safetyLevel;

	entry.push_back(Pair("safetylevel", safetyLevelValue));



}
UniValue certstats(const UniValue& params, bool fHelp) {
	if (fHelp || 2 < params.size())
		throw runtime_error("certstats unixtime=0 [\"alias\",...]\n"
				"Show statistics for all non-expired certificates. Only certificates created or updated after unixtime are returned. Set of certificates to look up based on array of aliases passed in. Leave empty for all certificates.\n");
	vector<string> aliases;
	uint64_t nExpireFilter = 0;
	if(params.size() >= 1)
		nExpireFilter = params[0].get_int64();
	if(params.size() >= 2)
	{
		if(params[1].isArray())
		{
			UniValue aliasesValue = params[1].get_array();
			for(unsigned int aliasIndex =0;aliasIndex<aliasesValue.size();aliasIndex++)
			{
				string lowerStr = aliasesValue[aliasIndex].get_str();
				boost::algorithm::to_lower(lowerStr);
				if(!lowerStr.empty())
					aliases.push_back(lowerStr);
			}
		}
		else
		{
			string aliasName =  params[1].get_str();
			boost::algorithm::to_lower(aliasName);
			if(!aliasName.empty())
				aliases.push_back(aliasName);
		}
	}
	UniValue oCertStats(UniValue::VOBJ);
	std::vector<CCert> certs;
	if (!pcertdb->GetDBCerts(certs, nExpireFilter, aliases))
		throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR ERRCODE: 2521 - " + _("Scan failed"));	
	if(!BuildCertStatsJson(certs, oCertStats))
		throw runtime_error("SYSCOIN_CERTIFICATE_RPC_ERROR ERRCODE: 2522 - " + _("Could not find this certificate"));

	return oCertStats;

}
/* Output some stats about certs
	- Total number of certs
*/
bool BuildCertStatsJson(const std::vector<CCert> &certs, UniValue& oCertStats)
{
	uint32_t totalCerts = certs.size();
	oCertStats.push_back(Pair("totalcerts", (int)totalCerts));
	UniValue oCerts(UniValue::VARR);
	BOOST_REVERSE_FOREACH(const CCert &cert, certs) {
		UniValue oCert(UniValue::VOBJ);
		CAliasIndex alias;
		CTransaction aliastx;
		if (!GetTxOfAlias(cert.vchAlias, alias, aliastx, true))
			continue;
		if(!BuildCertJson(cert, alias, oCert, "Yes"))
			continue;
		oCerts.push_back(oCert);
	}
	oCertStats.push_back(Pair("certs", oCerts)); 
	return true;
}



