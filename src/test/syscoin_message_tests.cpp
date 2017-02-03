#include "test/test_syscoin_services.h"
#include "utiltime.h"
#include "rpc/server.h"
#include "alias.h"
#include "cert.h"
#include <boost/test/unit_test.hpp>
BOOST_FIXTURE_TEST_SUITE (syscoin_message_tests, BasicSyscoinTestingSetup)

BOOST_AUTO_TEST_CASE (generate_big_msgdata)
{
	printf("Running generate_big_msgdata...\n");
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	AliasNew("node1", "jagmsg1", "password", "changeddata1");
	AliasNew("node2", "jagmsg2", "password", "changeddata2");
	AliasNew("node3", "jagmsg3", "password", "changeddata3");
	// 256 bytes long
	string goodtitle = "SfsdfddfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	// 1024*4 bytes long
	string gooddata =  "1111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111119762111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111197621111111111111111111976211111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
	// 1024*4 + 1 bytes long
	string baddata =   "11111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111111111111111111111111111111111111111111111111197621111111111111111111111111111111111111111111111111111111111111111976211111111111111111111111111111111111111111111111111111111111111119762111111111111111111197621111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111976211111111111111111119762111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

	string fromalias = "jagmsg1";
	string toalias = "jagmsg2";
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo " + toalias));
	string encryptionkeyto = find_value(r.get_obj(), "encryption_publickey").get_str();

	// good data cipher
	string strCipherGoodPrivateDataTo = "";
	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkeyto), gooddata, strCipherGoodPrivateDataTo), true);
	if(strCipherGoodPrivateDataTo.empty())
		strCipherGoodPrivateDataTo = "\"\"";
	else
		strCipherGoodPrivateDataTo = HexStr(strCipherGoodPrivateDataTo);
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo " + fromalias));
	string encryptionkeyfrom = find_value(r.get_obj(), "encryption_publickey").get_str();

	string strCipherGoodPrivateDataFrom = "";
	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkeyfrom), gooddata, strCipherGoodPrivateDataFrom), true);
	if(strCipherGoodPrivateDataFrom.empty())
		strCipherGoodPrivateDataFrom = "\"\"";
	else
		strCipherGoodPrivateDataFrom = HexStr(strCipherGoodPrivateDataFrom);

	// bad data cipher
	string strCipherBadPrivateDataTo = "";
	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkeyto), baddata, strCipherBadPrivateDataTo), true);
	if(strCipherBadPrivateDataTo.empty())
		strCipherBadPrivateDataTo = "\"\"";
	else
		strCipherBadPrivateDataTo = HexStr(strCipherBadPrivateDataTo);

	string strCipherBadPrivateDataFrom = "";
	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkeyfrom), baddata, strCipherBadPrivateDataFrom), true);
	if(strCipherBadPrivateDataFrom.empty())
		strCipherBadPrivateDataFrom = "\"\"";
	else
		strCipherBadPrivateDataFrom = HexStr(strCipherBadPrivateDataFrom);

	// if not sending from msg we can send 4kb in the to message
	BOOST_CHECK_NO_THROW(CallRPC("node1", "messagenew " + goodtitle + " " + strCipherGoodPrivateDataFrom + " " +  strCipherGoodPrivateDataTo + " " + fromalias + " " + toalias + " No"));
	GenerateBlocks(5);
	// ensure the from msg doesn't matter when not sending the from msg
	BOOST_CHECK_NO_THROW(CallRPC("node1", "messagenew " + goodtitle + " \"\" " +  strCipherGoodPrivateDataTo + " " + fromalias + " " + toalias + " No"));
	GenerateBlocks(5);
	// 1024 bytes long
	// largest from message allowed
	string goodfromdata = "asdfasdfdsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";	
	strCipherGoodPrivateDataFrom.clear();
	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkeyfrom), goodfromdata, strCipherGoodPrivateDataFrom), true);
	if(strCipherGoodPrivateDataFrom.empty())
		strCipherGoodPrivateDataFrom = "\"\"";
	else
		strCipherGoodPrivateDataFrom = HexStr(strCipherGoodPrivateDataFrom);
	// you can send from message if from msg is 1kb, so to msg would also be 1kb
	BOOST_CHECK_NO_THROW(CallRPC("node1", "messagenew " + goodtitle + " " + strCipherGoodPrivateDataFrom + " " +  strCipherGoodPrivateDataFrom + " " + fromalias + " " + toalias + " Yes"));
	GenerateBlocks(5);
	// ensure you can't send to msg of 4kb+1 when sending from msg (which is nothing)
	BOOST_CHECK_THROW(CallRPC("node1", "messagenew " + goodtitle + " \"\" " +  strCipherBadPrivateDataTo + " " + fromalias + " " + toalias + " Yes"), runtime_error);

	// can't send to msg with 4kb+1 even if not sending from msg
	BOOST_CHECK_THROW(CallRPC("node1", "messagenew " + goodtitle + " " + strCipherBadPrivateDataFrom + " " +  strCipherBadPrivateDataTo + " " + fromalias + " " + toalias + " No"), runtime_error);
	BOOST_CHECK_THROW(CallRPC("node1", "messagenew " + goodtitle + " \"\" " +  strCipherBadPrivateDataTo + " " + fromalias + " " + toalias + " No"), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_big_msgsubject)
{
	printf("Running generate_big_msgsubject...\n");
	GenerateBlocks(5);
	// 256 bytes long
	string goodtitle = "SfsdfddfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	// 1024 bytes long
	string gooddata = "asdfasdfdsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";	
	// 257 bytes long
	string badtitle =   "SfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";
	MessageNew("node1", "node2", goodtitle, gooddata, "jagmsg1", "jagmsg2");
	BOOST_CHECK_THROW(CallRPC("node1", "messagenew " + badtitle + " " + HexStr(vchFromString("message")) + " " + HexStr(vchFromString("message")) + " jagmsg1 jagmsg2"), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_msgaliastransfer)
{
	printf("Running generate_msgaliastransfer...\n");
	MessageNew("node1", "node2", "title", "data", "jagmsg1", "jagmsg2");
	// transfer an alias and send a message, the new node owner can now read messages to that alias
	AliasTransfer("node2", "jagmsg2", "node3", "changeddata2", "pvtdata");
	// send message to new node owning alias
	MessageNew("node1", "node3", "title", "data", "jagmsg1", "jagmsg2");
}
BOOST_AUTO_TEST_CASE (generate_messagepruning)
{
	UniValue r;
	// makes sure services expire in 100 blocks instead of 1 year of blocks for testing purposes
	printf("Running generate_messagepruning...\n");
	AliasNew("node1", "messageprune1", "password", "changeddata1");
	AliasNew("node2", "messageprune2", "password", "changeddata2");
	AliasNew("node3", "messageprune3", "password", "changeddata2");
	// stop node2 create a service,  mine some blocks to expire the service, when we restart the node the service data won't be synced with node2
	StopNode("node2");
	string guid = MessageNew("node1", "node3", "subject", "title", "messageprune1", "messageprune3");
	// messages expire by checking the recipient alias
	ExpireAlias("messageprune2");
	StartNode("node2");
	ExpireAlias("messageprune2");
	GenerateBlocks(5, "node2");
	// node1 will have the service still (its just expired)
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "messageinfo " + guid));
	// node2 shouldn't find the service at all (meaning node2 doesn't sync the data)
	BOOST_CHECK_THROW(CallRPC("node2", "messageinfo " + guid), runtime_error);
}
BOOST_AUTO_TEST_SUITE_END ()