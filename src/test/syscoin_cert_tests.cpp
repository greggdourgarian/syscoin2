#include "test/test_syscoin_services.h"
#include "utiltime.h"
#include "rpc/server.h"
#include "alias.h"
#include "cert.h"
#include "base58.h"
#include <boost/test/unit_test.hpp>
BOOST_FIXTURE_TEST_SUITE (syscoin_cert_tests, BasicSyscoinTestingSetup)

BOOST_AUTO_TEST_CASE (generate_big_certdata)
{
	printf("Running generate_big_certdata...\n");
	GenerateBlocks(5);
	AliasNew("node1", "jagcertbig1", "password", "data");
	// 256 bytes long
	string gooddata = "SfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";	
	// 257 bytes long
	string baddata = "SfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";	
	

	string strCipherBadData = "";
	string strCipherGoodData = "";
	CKey privKey;
	privKey.MakeNewKey(true);
	CPubKey pubKey = privKey.GetPubKey();
	vector<unsigned char> vchPubKey(pubKey.begin(), pubKey.end());
	BOOST_CHECK_EQUAL(EncryptMessage(vchPubKey, baddata, strCipherBadData), true);	
	BOOST_CHECK_EQUAL(EncryptMessage(vchPubKey, gooddata, strCipherGoodData), true);	
	string guid = CertNew("node1", "jagcertbig1", gooddata, gooddata);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certnew jagcertbig1 \"\" " + HexStr(vchFromString(strCipherGoodData))));
	BOOST_CHECK_THROW(CallRPC("node1", "certnew jagcertbig1 \"\" " + HexStr(vchFromString(strCipherBadData))), runtime_error);
	// unencrypted 257 bytes should cause us to trip 257+80 bytes once encrypted
	BOOST_CHECK_THROW(CallRPC("node1", "certnew jagcertbig1 " + gooddata + " " + HexStr(vchFromString(strCipherBadData))), runtime_error);
	// update cert with long pub data
	BOOST_CHECK_THROW(CallRPC("node1", "certupdate " + guid + " " + baddata + " " + HexStr(vchFromString(strCipherGoodData))), runtime_error);
	MilliSleep(2500);
	// trying to update to bad data for pub and priv
	BOOST_CHECK_THROW(CallRPC("node1", "certupdate " + guid + " " + baddata + " " + HexStr(vchFromString(strCipherBadData))), runtime_error);

}
BOOST_AUTO_TEST_CASE (generate_big_certpubdata)
{
	printf("Running generate_big_certpubdata...\n");
	GenerateBlocks(5);
	AliasNew("node1", "jagcertbig2", "password", "data");
	// 256 bytes long
	string gooddata = "SfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	// 257 bytes long
	string baddata =   "SfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";
	CertNew("node1", "jagcertbig2", gooddata, "\"\"");
	BOOST_CHECK_THROW(CallRPC("node1", "certnew jagcertbig2 " + baddata + " priv"), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_certupdate)
{
	printf("Running generate_certupdate...\n");
	AliasNew("node1", "jagcertupdate", "password", "data");
	string guid = CertNew("node1", "jagcertupdate", "data", "password");
	// update an cert that isn't yours
	BOOST_CHECK_THROW(CallRPC("node2", "certupdate " + guid + " pubdata data"), runtime_error);
	CertUpdate("node1", guid, "pub1");
	// shouldnt update data, just uses prev data because it hasnt changed
	CertUpdate("node1", guid);

}
BOOST_AUTO_TEST_CASE (generate_certtransfer)
{
	printf("Running generate_certtransfer...\n");
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	AliasNew("node1", "jagcert1", "password", "changeddata1");
	AliasNew("node2", "jagcert2", "password", "changeddata2");
	AliasNew("node3", "jagcert3", "password", "changeddata3");
	string guid, pvtguid, certdata;
	certdata = "certdata";
	guid = CertNew("node1", "jagcert1", "pubdata", certdata);
	// private cert
	pvtguid = CertNew("node1", "jagcert1", "pubdata", certdata);
	CertUpdate("node1", pvtguid, "pub3", certdata);
	UniValue r;
	CertTransfer("node1", "node2", guid, "jagcert2");
	CertTransfer("node1", "node3", pvtguid, "jagcert3");

	// xfer an cert that isn't yours
	BOOST_CHECK_THROW(CallRPC("node1", "certtransfer " + guid + " jagcert2"), runtime_error);

	// update xferred cert
	certdata = "newdata";
	CertUpdate("node2", guid, "public", certdata);

	// retransfer cert
	CertTransfer("node2","node3", guid, "jagcert3");
}
BOOST_AUTO_TEST_CASE (generate_certsafesearch)
{
	printf("Running generate_certsafesearch...\n");
	UniValue r;
	GenerateBlocks(1);
	AliasNew("node1", "jagsafesearch1", "password", "changeddata1");

	string certguidsafe = CertNew("node1", "jagsafesearch1", "public", "certdata");
	string certguidnotsafe = CertNew("node1", "jagsafesearch1", "public", "certdata");

	// shouldn't affect certinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe));

	// reverse the rolls
	CertUpdate("node1", certguidsafe, "pub", "certdata");
	CertUpdate("node1", certguidnotsafe,  "pub1", "certdata");

	// shouldn't affect certinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe));


}
BOOST_AUTO_TEST_CASE (generate_certban)
{
	printf("Running generate_certban...\n");
	UniValue r;
	GenerateBlocks(1);
	// cert is safe to search
	string certguidsafe = CertNew("node1", "jagsafesearch1", "pub", "certdata");
	// not safe to search
	string certguidnotsafe = CertNew("node1", "jagsafesearch1", "pub", "certdata");
	// can't ban on any other node than one that created sysban
	BOOST_CHECK_THROW(CertBan("node2",certguidnotsafe,SAFETY_LEVEL1), runtime_error);
	BOOST_CHECK_THROW(CertBan("node3",certguidsafe,SAFETY_LEVEL1), runtime_error);
	// ban both certs level 1 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidsafe,SAFETY_LEVEL1));
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidnotsafe,SAFETY_LEVEL1));
	// should be able to certinfo on level 1 banned certs
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe));
	
	// ban both certs level 2 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidsafe,SAFETY_LEVEL2));
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidnotsafe,SAFETY_LEVEL2));

	// shouldn't be able to certinfo on level 2 banned certs
	BOOST_CHECK_THROW(r = CallRPC("node1", "certinfo " + certguidsafe), runtime_error);
	BOOST_CHECK_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe), runtime_error);

	// unban both certs (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidsafe,0));
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidnotsafe,0));

	// should be able to certinfo on non banned certs
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe));
	
}

BOOST_AUTO_TEST_CASE (generate_certpruning)
{
	UniValue r;
	// makes sure services expire in 100 blocks instead of 1 year of blocks for testing purposes
	printf("Running generate_certpruning...\n");
	AliasNew("node1", "jagprune1", "password", "changeddata1");
	// stop node2 create a service,  mine some blocks to expire the service, when we restart the node the service data won't be synced with node2
	StopNode("node2");
	string guid = CertNew("node1", "jagprune1", "pub", "data");
	// we can find it as normal first
	
	AliasUpdate("node1", "jagprune1");
	GenerateBlocks(5, "node1");
	ExpireAlias("jagprune1");
	StartNode("node2");
	ExpireAlias("jagprune1");
	GenerateBlocks(5, "node2");

	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + guid));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_bool(), 1);	

	// should be pruned
	BOOST_CHECK_THROW(CallRPC("node2", "offerinfo " + guid), runtime_error);

	// stop node3
	StopNode("node3");
	// should fail: already expired alias
	BOOST_CHECK_THROW(CallRPC("node1", "aliasupdate sysrates.peg jagprune1 newdata \"\""), runtime_error);
	GenerateBlocks(5, "node1");
	// create a new service
	AliasNew("node1", "jagprune1", "password1", "temp", "data");
	string guid1 = CertNew("node1", "jagprune1", "pub", "data");
	// stop and start node1
	StopNode("node1");
	StartNode("node1");
	GenerateBlocks(5, "node1");
	// ensure you can still update before expiry
	CertUpdate("node1", guid1, "pubdata1", "privdata");
	// make sure our offer alias doesn't expire
	AliasUpdate("node1", "jagprune1");
	GenerateBlocks(5, "node1");
	ExpireAlias("jagprune1");
	// now it should be expired
	BOOST_CHECK_THROW(CallRPC("node1",  "certupdate " + guid1 + " pubdata3 newdata1"), runtime_error);
	GenerateBlocks(5, "node1");
	// and it should say its expired
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "certinfo " + guid1));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_bool(), 1);	
	GenerateBlocks(5, "node1");
	StartNode("node3");
	ExpireAlias("jagprune1");
	GenerateBlocks(5, "node3");
	// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
	BOOST_CHECK_THROW(CallRPC("node3", "certinfo " + guid1), runtime_error);
}
BOOST_AUTO_TEST_SUITE_END ()