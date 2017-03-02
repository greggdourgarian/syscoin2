#ifndef SYSCOIN_TEST_TEST_SYSCOIN_SERVICES_H
#define SYSCOIN_TEST_TEST_SYSCOIN_SERVICES_H

#include <stdio.h>
#include <univalue.h>
using namespace std;
/** Testing syscoin services setup that configures a complete environment with 3 nodes.
 */
UniValue CallRPC(const string &dataDir, const string& commandWithArgs, bool regTest = true, bool readJson = true);
void StartNode(const string &dataDir, bool regTest = true, const string& extraArgs="");
void StopNode(const string &dataDir="node1");
void StartNodes();
void StartMainNetNodes();
void StopMainNetNodes();
void StopNodes();
void GenerateBlocks(int nBlocks, const string& node="node1");
void GenerateMainNetBlocks(int nBlocks, const string& node);
string CallExternal(string &cmd);
void ExpireAlias(const string& alias);
void GetOtherNodes(const string& node, string& otherNode1, string& otherNode2);
void AliasBan(const string& node, const string& alias, int severity);
void OfferBan(const string& node, const string& offer, int severity);
void CertBan(const string& node, const string& cert, int severity);
string AliasNew(const string& node, const string& aliasname, const string &password, const string& pubdata, string privdata="\"\"");
string AliasUpdate(const string& node, const string& aliasname, const string& pubdata="\"\"", const string& privdata="\"\"", string password="\"\"", string addressStr = "\"\"");
void AliasTransfer(const string& node, const string& aliasname, const string& tonode, const string& pubdata="\"\"", const string& privdata="\"\"");
const string CertNew(const string& node, const string& alias, const string& pubdata, const string& data);
void CertUpdate(const string& node, const string& guid, const string& pubdata="\"\"", const string& data="\"\"");
void CertTransfer(const string& node, const string& tonode, const string& guid, const string& toalias);
const string MessageNew(const string& fromnode, const string& tonode, const string& pubdata, const string& privdata, const string& fromalias, const string& toalias);
void CreateSysRatesIfNotExist();
void CreateSysBanIfNotExist();
void CreateSysCategoryIfNotExist();
void OfferAcceptFeedback(const string& node, const string &alias, const string& offerguid, const string& acceptguid, const string& feedback, const string& rating, const char& user, const bool israting);
const UniValue FindOfferAcceptList(const string& node, const string& alias, const string& offerguid, const string& acceptguid, bool nocheck=false);
const UniValue FindOfferAcceptFeedback(const string& node, const string &alias, const string& offerguid, const string& acceptguid,const string& accepttxid, bool nocheck=false);
const string OfferNew(const string& node, const string& aliasname, const string& qty, const string& price, const string& details, const string& currency, const string& certguid="\"\"", const string& paymentoptions="\"\"");
void OfferUpdate(const string& node, const string& aliasname, const string& offerguid,  const string& qty="\"\"", const string& price="\"\"", const string& details="\"\"", const string& currency="\"\"", const string isprivate="\"\"", const string& certguid="\"\"", string commission="\"\"", string paymentoptions="\"\"");
void OfferAddWhitelist(const string& node,const string& offer, const string& aliasname, const string& discount);
void OfferRemoveWhitelist(const string& node, const string& offer, const string& aliasname);
void OfferClearWhitelist(const string& node, const string& offer);
void EscrowFeedback(const string& node, const string& role, const string& escrowguid, const string& feedbackprimary, const string& ratingprimary, char userprimary,const  string& feedbacksecondary, const string& ratingsecondary, char usersecondary, const bool israting);
const string OfferLink(const string& node, const string& alias, const string& guid, const string& commission, const string& newdetails);
const string OfferAccept(const string& ownernode, const string& node, const string& aliasname, const string& offerguid, const string& qty, const string& message);
const string LinkOfferAccept(const string& ownernode, const string& buyernode, const string& aliasname, const string& offerguid, const string& qty, const string& pay_message, const string& resellernode);
const string EscrowNew(const string& node, const string& sellernode, const string& buyeralias, const string& offerguid, const string& qty, const string& message, const string& arbiteralias, const string& selleralias, const string& discountexpected="\"\"");
void EscrowRelease(const string& node, const string& role, const string& guid);
void EscrowClaimRelease(const string& node, const string& guid);
void EscrowRefund(const string& node, const string& role, const string& guid);
void EscrowClaimRefund(const string& node, const string& guid);
// SYSCOIN testing setup
struct SyscoinTestingSetup {
    SyscoinTestingSetup();
    ~SyscoinTestingSetup();
};
struct BasicSyscoinTestingSetup {
    BasicSyscoinTestingSetup();
    ~BasicSyscoinTestingSetup();
};
struct SyscoinMainNetSetup {
	SyscoinMainNetSetup();
	~SyscoinMainNetSetup();
};
#endif
