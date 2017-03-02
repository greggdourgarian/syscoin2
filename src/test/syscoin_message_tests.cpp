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
	string goodprivdata =  "SfsdfddfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	// 257 bytes long
	string badprivdata =   "SfsdfddfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdda";

	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo " + toalias));
	string encryptionkey = find_value(r.get_obj(), "encryption_publickey").get_str();

	string strCipherGoodPrivateData = "";
	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkey), goodprivdata, strCipherGoodPrivateData), true);
	if(strCipherGoodPrivateData.empty())
		strCipherGoodPrivateData = "\"\"";
	else
		strCipherGoodPrivateData = HexStr(strCipherGoodPrivateData);

	string strCipherBadPrivateData = "";
	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkey), badprivdata, strCipherBadPrivateData), true);
	if(strCipherBadPrivateData.empty())
		strCipherBadPrivateData = "\"\"";
	else
		strCipherBadPrivateData = HexStr(strCipherBadPrivateData);

	string fromalias = "jagmsg1";
	string toalias = "jagmsg2";
	UniValue r;
	BOOST_CHECK_NO_THROW(CallRPC("node1", "messagenew " + strCipherGoodPrivateData + " " + strCipherGoodPrivateData + " " + fromalias + " " + toalias +  " " + HexStr(vchFromString("key1")) + HexStr(vchFromString("key2")) + HexStr(vchFromString("key3"))));
	GenerateBlocks(5);
	BOOST_CHECK_THROW(CallRPC("node1", "messagenew " + strCipherBadPrivateData + " " + strCipherGoodPrivateData + " " + fromalias + " " + toalias + " " + HexStr(vchFromString("key1")) + HexStr(vchFromString("key2")) + HexStr(vchFromString("key3"))), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_big_msgpubdata)
{
	printf("Running generate_big_msgpubdata...\n");
	GenerateBlocks(5);
	// 256 bytes long
	string gooddata = "SfsdfddfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";	
	// 257 bytes long
	string baddata =   "SfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";
	

	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo " + toalias));
	string encryptionkey = find_value(r.get_obj(), "encryption_publickey").get_str();

	string strCipherGoodPrivateData = "";
	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkey), gooddata, strCipherGoodPrivateData), true);
	if(strCipherGoodPrivateData.empty())
		strCipherGoodPrivateData = "\"\"";
	else
		strCipherGoodPrivateData = HexStr(strCipherGoodPrivateData);

	BOOST_CHECK_NO_THROW(CallRPC("node1", "messagenew " + strCipherGoodPrivateData + " " + gooddata + " jagmsg1 jagmsg2" + " " + HexStr(vchFromString("key1")) + HexStr(vchFromString("key2")) + HexStr(vchFromString("key3"))));
	GenerateBlocks(5);
	BOOST_CHECK_THROW(CallRPC("node1", "messagenew " + strCipherGoodPrivateData + " " + baddata + " jagmsg1 jagmsg2" + " " + HexStr(vchFromString("key1")) + HexStr(vchFromString("key2")) + HexStr(vchFromString("key3"))), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_msgaliastransfer)
{
	printf("Running generate_msgaliastransfer...\n");
	MessageNew("node1", "node2", "pubdata", "data", "jagmsg1", "jagmsg2");
	// transfer an alias and send a message, the new node owner can now read messages to that alias
	AliasTransfer("node2", "jagmsg2", "node3", "changeddata2", "pvtdata");
	// send message to new node owning alias
	MessageNew("node1", "node3", "pubdata", "data", "jagmsg1", "jagmsg2");
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
	string guid = MessageNew("node1", "node3", "pubdata", "msg", "messageprune1", "messageprune3");
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