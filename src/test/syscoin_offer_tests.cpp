#include "test/test_syscoin_services.h"
#include "utiltime.h"
#include "rpc/server.h"
#include "alias.h"
#include "cert.h"
#include "feedback.h"
#include <boost/test/unit_test.hpp>
BOOST_GLOBAL_FIXTURE( SyscoinTestingSetup );

BOOST_FIXTURE_TEST_SUITE (syscoin_offer_tests, BasicSyscoinTestingSetup)


BOOST_AUTO_TEST_CASE (generate_offernew)
{
	printf("Running generate_offernew...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias1", "password", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias1", "100", "0.05", "details", "USD");

	// should fail: generate an offer with unknown alias
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew fooalias details 100 0.05 USD"), runtime_error);

	// should fail: generate an offer with negative quantity
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew selleralias1 details -2 0.05 USD"), runtime_error);

	// should fail: generate an offer too-large details
	string s257bytes = "zSfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";	
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew selleralias1 " + s257bytes + " 100 0.05 USD"), runtime_error);

	// should fail: generate an offer with invalid currency
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew selleralias1 details 100 0.05 ZZZ"), runtime_error);
	// TODO test payment options
}

BOOST_AUTO_TEST_CASE (generate_certoffer)
{
	printf("Running generate_certoffer...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "node1alias", "password", "node1aliasdata");
	AliasNew("node1", "node1aliasa", "password", "node1aliasdata");
	AliasNew("node2", "node2alias", "password", "node2aliasdata");

	string certguid1  = CertNew("node1", "node1alias", "pub", "data");
	string certguid1a  = CertNew("node1", "node1aliasa", "pub", "data");
	string certguid2  = CertNew("node2", "node2alias", "pub", "data");

	// generate a good cert offer
	string offerguidnoncert = OfferNew("node1", "node1alias", "10", "0.05", "details", "USD");
	string offerguid = OfferNew("node1", "node1alias", "1", "0.05", "details", "USD", certguid1);
	string offerguid1 = OfferNew("node1", "node1alias", "1", "0.05", "details", "USD", certguid1);

	// must use certificates category for certoffer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias details 1 0.05 USD " + certguid1), runtime_error);

	// should fail: generate a cert offer using a quantity greater than 1
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias details 2 0.05 USD " + certguid1), runtime_error);

	// should fail: generate a cert offer using a zero quantity
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias details 0 0.05 USD " + certguid1), runtime_error);

	// should fail: generate a cert offer using an unlimited quantity
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias details -1 0.05 USD " + certguid1), runtime_error);

	// should fail: generate a cert offer using a cert guid you don't own
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias details 1 0.05 USD " + certguid2), runtime_error);	

	// update cert category to sub category of certificates
	OfferUpdate("node1", "node1alias", offerguid, "1", "0.15", "detailsnew", "USD", "No", certguid1);

	// change non cert offer to cert offer
	OfferUpdate("node1", "node1alias", offerguidnoncert, "1", "0.15", "detailsnew", "USD", "No", certguid1);


	// generate a cert offer if accepting only BTC
	OfferNew("node1", "node1alias", "1", "0.05", "details", "USD", certguid1, "BTC");
	// generate a cert offer if accepting BTC OR SYS
	OfferNew("node1", "node1alias", "1", "0.05", "details", "USD", certguid1, "SYS+BTC");

	// should fail: generate a cert offer using different alias for cert and offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias details 1 0.05 USD " + certguid1a), runtime_error);

	// should fail: generate a cert offer with invalid payment option
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias details 1 0.05 USD " + certguid1 + " BTC+SSS"), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_offerwhitelists)
{
	printf("Running generate_offerwhitelists...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "sellerwhitelistalias", "password", "changeddata1");
	AliasNew("node2", "selleraddwhitelistalias", "password", "changeddata1");
	AliasNew("node2", "selleraddwhitelistalias1", "password", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "sellerwhitelistalias", "100", "10.00", "details", "SYS");
	// add to whitelist
	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias", "5");
	BOOST_CHECK_THROW(CallRPC("node1", "offeraddwhitelist " + offerguid + " selleraddwhitelistalias 5"), runtime_error);
	// add to whitelist
	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias1", "6");
	// remove from whitelist
	OfferRemoveWhitelist("node1", offerguid, "selleraddwhitelistalias");
	BOOST_CHECK_THROW(CallRPC("node1", "offerremovewhitelist " + offerguid + " selleraddwhitelistalias"), runtime_error);

	AliasUpdate("node1", "sellerwhitelistalias", "changeddata2", "privdata2");
	AliasUpdate("node2", "selleraddwhitelistalias", "changeddata2", "privdata2");
	AliasUpdate("node2", "selleraddwhitelistalias1", "changeddata2", "privdata2");

	// add to whitelist
	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias", "4");
	OfferClearWhitelist("node1", offerguid);
	BOOST_CHECK_THROW(CallRPC("node1", "offerclearwhitelist " + offerguid), runtime_error);

	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias", "6");

	OfferAccept("node1", "node2", "selleraddwhitelistalias1", offerguid, "1", "message");

	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress selleraddwhitelistalias1 100"), runtime_error);
	GenerateBlocks(10);

	AliasUpdate("node1", "sellerwhitelistalias", "changeddata2", "privdata2");
	AliasUpdate("node2", "selleraddwhitelistalias", "changeddata2", "privdata2");
	AliasUpdate("node2", "selleraddwhitelistalias1", "changeddata2", "privdata2");

	OfferRemoveWhitelist("node1", offerguid, "selleraddwhitelistalias");

	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias", "1");
	OfferAccept("node1", "node2", "selleraddwhitelistalias1", offerguid, "1", "message");
	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias1", "2");


	OfferAccept("node1", "node2", "selleraddwhitelistalias1", offerguid, "1", "message");
	OfferClearWhitelist("node1", offerguid);


}
BOOST_AUTO_TEST_CASE (generate_offernew_linkedoffer)
{
	printf("Running generate_offernew_linkedoffer...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias5", "password", "changeddata1");
	AliasNew("node2", "selleralias6", "password", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias5", "100", "10.00", "details", "USD", "\"\"");
	OfferAddWhitelist("node1", offerguid, "selleralias6", "5");
	string lofferguid = OfferLink("node2", "selleralias6", offerguid, "5", "newdetails");

	// it was already added to whitelist, remove it and add it as 5% discount
	OfferRemoveWhitelist("node1", offerguid, "selleralias6");
	OfferAddWhitelist("node1", offerguid, "selleralias6", "5");
	
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offerinfo " + lofferguid));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), "10.50");

	// generate a cert offer using a negative percentage bigger or equal to than discount which was set to 5% (uses -5 in calculcation)
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink selleralias6 " + offerguid + " -5 newdetails"), runtime_error);	


	// should fail: generate a cert offer using too-large pergentage
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink selleralias6 " + offerguid + " 101 newdetails"), runtime_error);	

	// should fail: generate an offerlink with too-large details
	string s257bytes = "zSfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";	
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink selleralias6 " + offerguid + " 5 " + s257bytes), runtime_error);

	// let the offer expire
	ExpireAlias("selleralias6");
	// should fail: try to link against an expired offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerlink selleralias6 " + offerguid + " 5 newdetails"), runtime_error);
	
}

BOOST_AUTO_TEST_CASE (generate_offernew_linkedofferexmode)
{
	printf("Running generate_offernew_linkedofferexmode...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias8", "password", "changeddata1");
	AliasNew("node2", "selleralias9", "password", "changeddata1");

	// generate a good offer 
	string offerguid = OfferNew("node1", "selleralias8", "100", "0.05", "details", "USD");

	// should fail: attempt to create a linked offer for a product without being on the whitelist
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink selleralias9 " + offerguid + " 5 newdetails"), runtime_error);

	OfferAddWhitelist("node1", offerguid, "selleralias9", "5");

	// should succeed: attempt to create a linked offer for a product while being on the whitelist
	OfferLink("node2", "selleralias9", offerguid, "5", "newdetails");
}

BOOST_AUTO_TEST_CASE (generate_offernew_linkedlinkedoffer)
{
	printf("Running generate_offernew_linkedlinkedoffer...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias12", "password", "changeddata1");
	AliasNew("node2", "selleralias13", "password", "changeddata1");
	AliasNew("node3", "selleralias14", "password", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias12", "100", "0.05", "details", "USD", "\"\"");
	OfferAddWhitelist("node1", offerguid, "selleralias13", "5");

	string lofferguid = OfferLink("node2", "selleralias13", offerguid, "5", "newdetails");

	// should fail: try to generate a linked offer with a linked offer
	BOOST_CHECK_THROW(r = CallRPC("node3", "offerlink selleralias14 " + lofferguid + " 5 newdetails"), runtime_error);

}

BOOST_AUTO_TEST_CASE (generate_offerupdate)
{
	printf("Running generate_offerupdate...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias2", "password", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias2", "100", "0.05", "detaiils", "USD");

	// perform a valid update
	OfferUpdate("node1", "selleralias2", offerguid, "90", "0.15", "newdetails");

	// should fail: offer cannot be updated by someone other than owner
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerupdate selleralias2 " + offerguid + " 90 0.15 details"), runtime_error);


	// should fail: generate an offer with unknown alias
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerupdate fooalias " + offerguid + " 90 0.15 details"), runtime_error);

	string s257bytes =   "dSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";
	// should fail: generate an offer too-large details
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerupdate selleralias2 " + offerguid + " 90 0.15 " + s257bytes), runtime_error);

	// don't update any info
	OfferUpdate("node1", "selleralias2", offerguid);

}

BOOST_AUTO_TEST_CASE (generate_offerupdate_editcurrency)
{
	printf("Running generate_offerupdate_editcurrency...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleraliascurrency", "password", "changeddata1");
	AliasNew("node2", "buyeraliascurrency", "password", "changeddata2");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleraliascurrency", "100", "0.05", "details", "USD");
	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress buyeraliascurrency 10000"), runtime_error);
	GenerateBlocks(10);
	// accept and confirm payment is accurate with usd
	string acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "2", "message");
	UniValue acceptRet = FindOfferAcceptList("node1", "selleraliascurrency", offerguid, acceptguid);
	CAmount nTotal = find_value(acceptRet, "systotal").get_int64();
	// 2690.1 SYS/USD
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(2*0.05*2690.1));

	// perform a valid update
	OfferUpdate("node1", "selleraliascurrency", offerguid, "90", "0.15", "detailsnew", "CAD");
	// accept and confirm payment is accurate with cad
	acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "3", "message");
	acceptRet = FindOfferAcceptList("node1", "selleraliascurrency", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	// 2698.0 SYS/CAD
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(3*0.15*2698.0));

	AliasUpdate("node1", "selleraliascurrency", "changeddata2", "privdata2");
	AliasUpdate("node2", "buyeraliascurrency", "changeddata2", "privdata2");


	OfferUpdate("node1", "selleraliascurrency", offerguid, "90", "1.00", "detailsnew", "SYS");
	// accept and confirm payment is accurate with sys
	acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "3", "message");
	acceptRet = FindOfferAcceptList("node1", "selleraliascurrency", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	// 1 SYS/SYS
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(3));

	OfferUpdate("node1", "selleraliascurrency", offerguid, "90", "0.00001000", "detailsnew", "BTC");
	// accept and confirm payment is accurate with btc
	acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "4", "message");
	acceptRet = FindOfferAcceptList("node1", "selleraliascurrency", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	// 100000.0 SYS/BTC
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(4*0.00001000*100000.0));

	// try to update currency and accept in same block, ensure payment uses old currency not new
	BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate selleraliascurrency " + offerguid + " 90 0.2 desc EUR"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offeraccept buyeraliascurrency " + offerguid + " 10 message"));
	const UniValue &arr = r.get_array();
	acceptguid = arr[1].get_str();
	GenerateBlocks(2);
	GenerateBlocks(3);
	GenerateBlocks(5, "node2");
	acceptRet = FindOfferAcceptList("node1", "selleraliascurrency", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	// still used BTC conversion amount
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(10*0.00001000*100000.0));
	// 2695.2 SYS/EUR
	acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "3", "message");
	acceptRet = FindOfferAcceptList("node1", "selleraliascurrency", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(3*0.2*2695.2));

	// linked offer with root and linked offer changing currencies

	// external payments


}
BOOST_AUTO_TEST_CASE (generate_offeraccept)
{
	printf("Running generate_offeraccept...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias3", "password", "somedata");
	AliasNew("node2", "buyeralias3", "password", "somedata");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias3", "100", "0.01", "details", "USD");
	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress buyeralias3 10000"), runtime_error);
	GenerateBlocks(10);
	// perform a valid accept
	string acceptguid = OfferAccept("node1", "node2", "buyeralias3", offerguid, "1", "message");

	// should fail: generate an offer accept with too-large message
	string s257bytes = "zSfsddfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";	
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo selleralias3"));
	string encryptionkey = find_value(r.get_obj(), "encryption_publickey").get_str();
	string strCipherData = "";

	BOOST_CHECK_EQUAL(EncryptMessage(ParseHex(encryptionkey), s257bytes, strCipherData), true);
	
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias3 " + offerguid + " 1 " + HexStr(vchFromString(strCipherData))), runtime_error);

	// perform an accept on negative quantity
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias3 " + offerguid + " -1 " + HexStr(vchFromString("message"))), runtime_error);

	// perform an accept on zero quantity
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias3 " + offerguid + " 0 " +  HexStr(vchFromString("message"))), runtime_error);

	// perform an accept on more items than available
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias3 " + offerguid + " 100 " +  HexStr(vchFromString("message"))), runtime_error);


}
BOOST_AUTO_TEST_CASE (generate_linkedaccept)
{
	printf("Running generate_linkedaccept...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "node1aliaslinked", "password", "node1aliasdata");
	AliasNew("node2", "node2aliaslinked", "password", "node2aliasdata");
	AliasNew("node3", "node3aliaslinked", "password", "node2aliasdata");

	string offerguid = OfferNew("node1", "node1aliaslinked",  "10", "0.05", "details", "USD", "\"\"");
	OfferAddWhitelist("node1", offerguid, "node2aliaslinked", "0");
	string lofferguid = OfferLink("node2", "node2aliaslinked", offerguid, "5", "newdetails");
	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress node3aliaslinked 850"), runtime_error);
	GenerateBlocks(10);
	LinkOfferAccept("node1", "node3", "node3aliaslinked", lofferguid, "6", "message", "node2");
}
BOOST_AUTO_TEST_CASE (generate_cert_linkedaccept)
{
	printf("Running generate_cert_linkedaccept...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "node1alias", "password1", "node1aliasdata");
	AliasNew("node2", "node2alias", "password2", "node2aliasdata");
	AliasNew("node3", "node3alias", "password3", "node2aliasdata");

	string certguid  = CertNew("node1", "node1alias", "pubdata", "data");
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguid));
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == "node1alias");
	// generate a good cert offer
	string offerguid = OfferNew("node1", "node1alias", "1", "0.05", "details", "USD", certguid);
	OfferAddWhitelist("node1", offerguid, "node2alias", "0");
	string lofferguid = OfferLink("node2", "node2alias", offerguid, "5", "newdetails");

	AliasUpdate("node1", "node1alias", "changeddata2", "privdata2");
	AliasUpdate("node2", "node2alias", "changeddata2", "privdata2");
	AliasUpdate("node3", "node3alias", "changeddata3", "privdata3");
	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress node3alias 135"), runtime_error);
	GenerateBlocks(10);
	LinkOfferAccept("node1", "node3", "node3alias", lofferguid, "1", "message", "node2");
	GenerateBlocks(5, "node1");
	GenerateBlocks(5, "node3");
	// cert does not get transferred, need to do it manually after the sale
	BOOST_CHECK_NO_THROW(r = CallRPC("node3", "certinfo " + certguid));
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == "node1alias");
}
BOOST_AUTO_TEST_CASE (generate_offeracceptfeedback)
{
	printf("Running generate_offeracceptfeedback...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleraliasfeedback", "password", "somedata");
	AliasNew("node2", "buyeraliasfeedback", "password", "somedata");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleraliasfeedback", "100", "0.01", "details", "USD");
	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress buyeraliasfeedback 50"), runtime_error);
	GenerateBlocks(10);
	// perform a valid accept
	string acceptguid = OfferAccept("node1", "node2", "buyeraliasfeedback", offerguid, "1", "message");
	// seller leaves feedback first
	OfferAcceptFeedback("node1", "selleraliasfeedback", offerguid, acceptguid, "feedbackseller", "1", FEEDBACKSELLER, true);
	// seller can leave feedback twice in a row
	OfferAcceptFeedback("node1", "selleraliasfeedback", offerguid, acceptguid, "feedbackseller", "1", FEEDBACKSELLER, false);

	// then buyer can leave feedback
	OfferAcceptFeedback("node2","buyeraliasfeedback", offerguid, acceptguid, "feedbackbuyer", "5", FEEDBACKBUYER, true);
	// can leave feedback twice in  arow
	OfferAcceptFeedback("node2","buyeraliasfeedback", offerguid, acceptguid, "feedbackbuyer2", "5", FEEDBACKBUYER, false);

	// create up to 10 replies each
	for(int i =0;i<8;i++)
	{
		// keep alive
		OfferUpdate("node1", "selleraliasfeedback", offerguid, "90", "0.01", "detailsnew", "USD");
		// seller can reply but not rate
		OfferAcceptFeedback("node1",  "selleraliasfeedback",offerguid, acceptguid, "feedbackseller1", "2", FEEDBACKSELLER, false);

		// buyer can reply but not rate
		OfferAcceptFeedback("node2", "buyeraliasfeedback", offerguid, acceptguid, "feedbackbuyer1", "3", FEEDBACKBUYER, false);
		
	}
	string offerfeedbackstr = "offeracceptfeedback " + offerguid + " " + acceptguid + " testfeedback 1";
	// now you can't leave any more feedback as a seller
	BOOST_CHECK_THROW(r = CallRPC("node1", offerfeedbackstr), runtime_error);

	// perform a valid accept
	acceptguid = OfferAccept("node1", "node2", "buyeraliasfeedback", offerguid, "1", "message");
	GenerateBlocks(5, "node2");
	// this time buyer leaves feedback first
	OfferAcceptFeedback("node2","buyeraliasfeedback", offerguid, acceptguid, "feedbackbuyer", "1", FEEDBACKBUYER, true);
	// buyer can leave feedback three times in a row
	OfferAcceptFeedback("node2", "buyeraliasfeedback",offerguid, acceptguid, "feedbackbuyer", "1", FEEDBACKBUYER, false);
	OfferAcceptFeedback("node2", "buyeraliasfeedback",offerguid, acceptguid, "feedbackbuyer", "1", FEEDBACKBUYER, false);

	// then seller can leave feedback
	OfferAcceptFeedback("node1", "selleraliasfeedback",offerguid, acceptguid, "feedbackseller", "5", FEEDBACKSELLER, true);
	OfferAcceptFeedback("node1", "selleraliasfeedback",offerguid, acceptguid, "feedbackseller2", "4", FEEDBACKSELLER, false);
	OfferAcceptFeedback("node1", "selleraliasfeedback",offerguid, acceptguid, "feedbackseller2", "4", FEEDBACKSELLER, false);
}
BOOST_AUTO_TEST_CASE (generate_offerexpired)
{
	printf("Running generate_offerexpired...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias4", "password", "somedata");
	AliasNew("node2", "buyeralias4", "password", "somedata");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias4", "100", "0.01", "details", "USD");
	OfferAddWhitelist("node1", offerguid, "buyeralias4", "5");
	// this will expire the offer
	ExpireAlias("buyeralias4");

	// should fail: perform an accept on expired offer
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias4 " + offerguid + " 1 " + HexStr(vchFromString("message"))), runtime_error);

	// should fail: offer update on an expired offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerupdate selleralias4 " + offerguid + " 90 0.15 details"), runtime_error);
	
	// should fail: link to an expired offer
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink buyeralias4 " + offerguid + " 5 newdetails"), runtime_error);	
	

}

BOOST_AUTO_TEST_CASE (generate_offerexpiredexmode)
{
	printf("Running generate_offerexpiredexmode...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias10", "password", "changeddata1");
	AliasNew("node2", "selleralias11", "password", "changeddata1");

	// generate a good offer 
	string offerguid = OfferNew("node1", "selleralias10", "100", "0.05", "details", "USD");

	// should succeed: offer seller adds affiliate to whitelist
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offeraddwhitelist " + offerguid + " selleralias11 10"));
	ExpireAlias("selleralias10");

	// should fail: remove whitelist item from expired offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerremovewhitelist " + offerguid + " selleralias11"), runtime_error);
	// should fail: clear whitelist from expired offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerclearwhitelist " + offerguid), runtime_error);

}

BOOST_AUTO_TEST_CASE (generate_certofferexpired)
{
	printf("Running generate_certofferexpired...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "node1alias2a", "password", "node1aliasdata");
	AliasNew("node1", "node1alias2", "password", "node1aliasdata");
	AliasNew("node2", "node2alias2", "password", "node2aliasdata");

	string certguid  = CertNew("node1", "node1alias2", "pubdata", "data");
	string certguid1  = CertNew("node1", "node1alias2a", "pubdata", "data");

	GenerateBlocks(5);

	// generate a good cert offer
	string offerguid = OfferNew("node1", "node1alias2", "1", "0.05", "details", "USD", certguid);
	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress node2alias2 125"), runtime_error);
	GenerateBlocks(10);
	OfferAccept("node1", "node2", "node2alias2", offerguid, "1", "message");
	offerguid = OfferNew("node1", "node1alias2", "1", "0.05", "details", "USD", certguid);
	ExpireAlias("node2alias2");
	// should fail: accept an offer with expired alias
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept node2alias2 " + offerguid + " 1 " +  HexStr(vchFromString("message"))), runtime_error);
	// should fail: generate a cert offer using an expired cert
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias2 details 1 0.05 USD " + certguid1), runtime_error);
	/// should fail: generate a cert offer using an expired cert
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias2 details 1 0.05 USD " + certguid), runtime_error);
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
}
BOOST_AUTO_TEST_CASE (generate_offersafesearch)
{
	printf("Running generate_offersafesearch...\n");
	UniValue r;
	GenerateBlocks(10);
	GenerateBlocks(10, "node2");
	AliasNew("node2", "selleralias15", "changeddata2", "privdata2");
	// offer is safe to search
	string offerguidsafe = OfferNew("node2", "selleralias15", "100", "10.00", "details", "USD");
	// not safe to search
	string offerguidnotsafe = OfferNew("node2", "selleralias15", "100", "10.00", "details", "USD");


	// shouldn't affect offerinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe));

	// reverse the rolls
	OfferUpdate("node2", "selleralias15", offerguidsafe, "90", "0.15", "detailsnew", "USD", "No");
	OfferUpdate("node2", "selleralias15", offerguidnotsafe,  "90", "0.15", "detailsnew", "USD", "No");


	// shouldn't affect offerinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe));


}
BOOST_AUTO_TEST_CASE (generate_offerban)
{
	printf("Running generate_offerban...\n");
	UniValue r;
	GenerateBlocks(10);
	GenerateBlocks(10, "node2");
	AliasNew("node2", "selleralias15ban", "changeddata2", "privdata2");
	// offer is safe to search
	string offerguidsafe = OfferNew("node2", "selleralias15ban", "100", "10.00", "details", "USD");
	// not safe to search
	string offerguidnotsafe = OfferNew("node2", "selleralias15ban", "100", "10.00", "details", "USD");
	// can't ban on any other node than one that created sysban
	BOOST_CHECK_THROW(OfferBan("node2",offerguidnotsafe,SAFETY_LEVEL1), runtime_error);
	BOOST_CHECK_THROW(OfferBan("node3",offerguidsafe,SAFETY_LEVEL1), runtime_error);
	// ban both offers level 1 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidsafe,SAFETY_LEVEL1));
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidnotsafe,SAFETY_LEVEL1));
	// should be able to offerinfo on level 1 banned offers
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe));
	
	// ban both offers level 2 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidsafe,SAFETY_LEVEL2));
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidnotsafe,SAFETY_LEVEL2));

	// shouldn't be able to offerinfo on level 2 banned offers
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe), runtime_error);
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe), runtime_error);

	// unban both offers (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidsafe,0));
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidnotsafe,0));

	// should be able to offerinfo on non banned offers
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe));
	
}
BOOST_AUTO_TEST_CASE (generate_offerpruning)
{
	UniValue r;
	// makes sure services expire in 100 blocks instead of 1 year of blocks for testing purposes

	printf("Running generate_offerpruning...\n");
	AliasNew("node1", "pruneoffer", "password", "changeddata1");
	// stop node2 create a service,  mine some blocks to expire the service, when we restart the node the service data won't be synced with node2
	StopNode("node2");
	string guid = OfferNew("node1", "pruneoffer", "1", "0.05", "details", "USD");
	GenerateBlocks(5, "node1");
	// then we let the service expire
	ExpireAlias("pruneoffer");
	StartNode("node2");
	ExpireAlias("pruneoffer");
	GenerateBlocks(5, "node2");

	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + guid));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_bool(), 1);	

	// should be pruned
	BOOST_CHECK_THROW(CallRPC("node2", "offerinfo " + guid), runtime_error);

	// stop node3
	StopNode("node3");
	// should fail: already expired alias
	BOOST_CHECK_THROW(CallRPC("node1", "aliasupdate sysrates.peg pruneoffer newdata privdata"), runtime_error);
	GenerateBlocks(5, "node1");
	// create a new service
	AliasNew("node1", "pruneoffer", "password1", "data");
	string guid1 = OfferNew("node1", "pruneoffer", "1", "0.05", "details", "USD");
	// stop and start node1
	StopNode("node1");
	StartNode("node1");
	GenerateBlocks(5, "node1");
	// ensure you can still update before expiry
	OfferUpdate("node1", "pruneoffer", guid1, "1", "0.05", "details");
	GenerateBlocks(5, "node1");
	// make sure our offer alias doesn't expire
	AliasUpdate("node1", "pruneoffer");
	ExpireAlias("pruneoffer");
	// now it should be expired
	BOOST_CHECK_THROW(CallRPC("node1", "offerupdate pruneoffer " + guid1 + " 1 0.05 details"), runtime_error);
	// and it should say its expired
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offerinfo " + guid1));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_bool(), 1);	
	GenerateBlocks(5, "node1");
	StartNode("node3");
	ExpireAlias("pruneoffer");
	GenerateBlocks(5, "node3");
	// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
	BOOST_CHECK_THROW(CallRPC("node3", "offerinfo " + guid1), runtime_error);

}

BOOST_AUTO_TEST_SUITE_END ()