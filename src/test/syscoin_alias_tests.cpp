#include "test/test_syscoin_services.h"
#include "utiltime.h"
#include "rpcserver.h"
#include "alias.h"
#include <boost/test/unit_test.hpp>
BOOST_GLOBAL_FIXTURE( SyscoinTestingSetup );

BOOST_FIXTURE_TEST_SUITE (syscoin_alias_tests, BasicSyscoinTestingSetup)

BOOST_AUTO_TEST_CASE (generate_sysrates_alias)
{
	printf("Running generate_sysrates_alias...\n");
	CreateSysRatesIfNotExist();
	CreateSysBanIfNotExist();
	CreateSysCategoryIfNotExist();
}
BOOST_AUTO_TEST_CASE (generate_big_aliasdata)
{
	printf("Running generate_big_aliasdata...\n");
	GenerateBlocks(5);
	// 1023 bytes long
	string gooddata = "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";
	// 1024 bytes long
	string baddata =   "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsdz";
	AliasNew("node1", "jag", gooddata);
	BOOST_CHECK_THROW(CallRPC("node1", "aliasnew jag1 " + baddata), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_big_aliasname)
{
	printf("Running generate_big_aliasname...\n");
	GenerateBlocks(5);
	// 255 bytes long
	string goodname = "SfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	// 1023 bytes long
	string gooddata = "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";	
	// 256 bytes long
	string badname =   "SfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";
	AliasNew("node1", goodname, "a");
	BOOST_CHECK_THROW(CallRPC("node1", "aliasnew " + badname + " 3d"), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_aliasupdate)
{
	printf("Running generate_aliasupdate...\n");
	GenerateBlocks(1);
	AliasNew("node1", "jagupdate", "data");
	// update an alias that isn't yours
	BOOST_CHECK_THROW(CallRPC("node2", "aliasupdate jagupdate test"), runtime_error);
	AliasUpdate("node1", "jagupdate", "changeddata", "privdata");
	// shouldnt update data, just uses prev data because it hasnt changed
	AliasUpdate("node1", "jagupdate", "changeddata", "privdata");

}
BOOST_AUTO_TEST_CASE (generate_sendmoneytoalias)
{
	printf("Running generate_sendmoneytoalias...\n");
	GenerateBlocks(5, "node2");
	AliasNew("node2", "sendnode2", "changeddata2");
	UniValue r;
	// get balance of node2 first to know we sent right amount oater
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "getinfo"));
	CAmount balanceBefore = AmountFromValue(find_value(r.get_obj(), "balance"));
	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress sendnode2 1.335"), runtime_error);
	GenerateBlocks(10);
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "getinfo"));
	// 54.13 since 1 block matures
	balanceBefore += 1.335*COIN + 54.13*COIN;
	CAmount balanceAfter = AmountFromValue(find_value(r.get_obj(), "balance"));
	BOOST_CHECK_EQUAL(balanceBefore, balanceAfter);
}
BOOST_AUTO_TEST_CASE (generate_aliastransfer)
{
	printf("Running generate_aliastransfer...\n");
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	UniValue r;
	string strPubKey1 = AliasNew("node1", "jagnode1", "changeddata1");
	string strPubKey2 = AliasNew("node2", "jagnode2", "changeddata2");
	UniValue pkr = CallRPC("node2", "generatepublickey");
	BOOST_CHECK(pkr.type() == UniValue::VARR);
	const UniValue &resultArray = pkr.get_array();
	string newPubkey = resultArray[0].get_str();	
	AliasTransfer("node1", "jagnode1", "node2", "changeddata1", "pvtdata");

	// xfer an alias that isn't yours
	BOOST_CHECK_THROW(r = CallRPC("node1", "aliasupdate jagnode1 changedata1 pvtdata " + newPubkey), runtime_error);

	// trasnfer alias and update it at the same time
	AliasTransfer("node2", "jagnode2", "node3", "changeddata4", "pvtdata");

	// update xferred alias
	AliasUpdate("node2", "jagnode1", "changeddata5", "pvtdata1");

	// retransfer alias
	AliasTransfer("node2", "jagnode1", "node3", "changeddata5", "pvtdata2");

	// xfer an alias to another alias is prohibited
	BOOST_CHECK_THROW(r = CallRPC("node2", "aliasupdate jagnode2 changedata1 pvtdata " + strPubKey1), runtime_error);
	
}
BOOST_AUTO_TEST_CASE (generate_aliassafesearch)
{
	printf("Running generate_aliassafesearch...\n");
	UniValue r;
	GenerateBlocks(1);
	// alias is safe to search
	AliasNew("node1", "jagsafesearch", "pubdata", "privdata", "Yes");
	// not safe to search
	AliasNew("node1", "jagnonsafesearch", "pubdata", "privdata", "No");
	// should include result in both safe search mode on and off
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagsafesearch", "Yes"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagsafesearch", "No"), true);

	// should only show up if safe search is off
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagnonsafesearch", "Yes"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagnonsafesearch", "No"), true);

	// shouldn't affect aliasinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagsafesearch"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagnonsafesearch"));


}
BOOST_AUTO_TEST_CASE (generate_aliasban)
{
	printf("Running generate_aliasban...\n");
	UniValue r;
	GenerateBlocks(1);
	// 2 aliases, one will be banned that is safe searchable other is banned that is not safe searchable
	AliasNew("node1", "jagbansafesearch", "pubdata", "privdata", "Yes");
	AliasNew("node1", "jagbannonsafesearch", "pubdata", "privdata", "No");
	// can't ban on any other node than one that created SYS_BAN
	BOOST_CHECK_THROW(AliasBan("node2","jagbansafesearch",SAFETY_LEVEL1), runtime_error);
	BOOST_CHECK_THROW(AliasBan("node3","jagbansafesearch",SAFETY_LEVEL1), runtime_error);
	// ban both aliases level 1 (only owner of SYS_CATEGORY can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearch",SAFETY_LEVEL1));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearch",SAFETY_LEVEL1));
	// should only show level 1 banned if safe search filter is not used
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "Yes"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "No"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "Yes"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "No"), true);
	// should be able to aliasinfo on level 1 banned aliases
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagbansafesearch"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagbannonsafesearch"));
	
	// ban both aliases level 2 (only owner of SYS_CATEGORY can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearch",SAFETY_LEVEL2));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearch",SAFETY_LEVEL2));
	// no matter what filter won't show banned aliases
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "Yes"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "No"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "Yes"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "No"), false);

	// shouldn't be able to aliasinfo on level 2 banned aliases
	BOOST_CHECK_THROW(r = CallRPC("node1", "aliasinfo jagbansafesearch"), runtime_error);
	BOOST_CHECK_THROW(r = CallRPC("node1", "aliasinfo jagbannonsafesearch"), runtime_error);

	// unban both aliases (only owner of SYS_CATEGORY can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearch",0));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearch",0));
	// safe to search regardless of filter
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "Yes"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "No"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "Yes"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "No"), true);

	// should be able to aliasinfo on non banned aliases
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagbansafesearch"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagbannonsafesearch"));
	
}
BOOST_AUTO_TEST_CASE (generate_aliaspruning)
{
	UniValue r;
	// makes sure services expire in 100 blocks instead of 1 year of blocks for testing purposes
	#ifdef ENABLE_DEBUGRPC
		printf("Running generate_aliaspruning...\n");
		// stop node2 create a service,  mine some blocks to expire the service, when we restart the node the service data won't be synced with node2
		StopNode("node2");
		AliasNew("node1", "aliasprune", "data");
		// we can find it as normal first
		BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune", "No"), true);
		// then we let the service expire
		GenerateBlocks(100);
		StartNode("node2");
		GenerateBlocks(5, "node2");
		// now we shouldn't be able to search it
		BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune", "No"), false);
		// and it should say its expired
		BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo aliasprune"));
		BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 1);	

		// node2 shouldn't find the service at all (meaning node2 doesn't sync the data)
		BOOST_CHECK_THROW(CallRPC("node2", "aliasinfo aliasprune"), runtime_error);
		BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasprune", "No"), false);

		// stop node3
		StopNode("node3");
		// create a new service
		AliasNew("node1", "aliasprune1", "data");
		// make 79 blocks (20 get mined with new)
		GenerateBlocks(79);
		// stop and start node1
		StopNode("node1");
		StartNode("node1");
		// ensure you can still update before expiry
		AliasUpdate("node1", "aliasprune1", "newdata","privdata");
		// you can search it still on node1/node2
		BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune", "No"), true);
		BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasprune", "No"), true);
		// generate 79 more blocks (20 get mined from update)
		GenerateBlocks(79);
		// ensure service is still active since its supposed to expire at 100 blocks of non updated services
		AliasUpdate("node1", "aliasprune1", "newdata1","privdata");
		// you can search it still on node1/node2
		BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune", "No"), true);
		BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasprune", "No"), true);

		GenerateBlocks(100);
		// now it should be expired
		BOOST_CHECK_THROW(r = CallRPC("node2", "aliasupdate aliasprune1 newdata2 privdata"), runtime_error);
		BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune", "No"), false);
		BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasprune", "No"), false);
		// and it should say its expired
		BOOST_CHECK_NO_THROW(r = CallRPC("node2", "aliasinfo aliasprune1"));
		BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 1);	

		StartNode("node3");
		GenerateBlocks(5, "node3");
		// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
		BOOST_CHECK_THROW(CallRPC("node3", "aliasinfo aliasprune1"), runtime_error);
		BOOST_CHECK_EQUAL(AliasFilter("node3", "aliasprune1", "No"), false);
	#endif
}
BOOST_AUTO_TEST_SUITE_END ()