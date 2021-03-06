package org.bitcoinj.core;

import java.math.BigInteger;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: HashEngineering
 * Date: 8/13/13
 * Time: 7:23 PM
 * To change this template use File | Settings | File Templates.
 */
public class CoinDefinition {


    public static final String coinName = "Worldleadcurrency";
    public static final String coinTicker = "WLC";
    public static final String coinURIScheme = "worldleadcurrency";
    public static final String cryptsyMarketId = "29";
    public static final String cryptsyMarketCurrency = "BTC";
    public static final String PATTERN_PRIVATE_KEY_START = "[5]";
    public static final String PATTERN_PRIVATE_KEY_START_COMPRESSED = "[L]";
    public static final String PATTERN_PRIVATE_KEY_START_TESTNET = "9";
    public static final String PATTERN_PRIVATE_KEY_START_COMPRESSED_TESTNET = "c";

    public static String lowerCaseCoinName() { return coinName.toLowerCase(); }

    public enum CoinPrecision {
        Coins,
        Millicoins,
    }
    public static final CoinPrecision coinPrecision = CoinPrecision.Coins;


    public static final String BLOCKEXPLORER_BASE_URL_PROD = "http://109.73.173.119:81/";    //blockr.io
    public static final String BLOCKEXPLORER_ADDRESS_PATH = "address/";             //blockr.io path
    public static final String BLOCKEXPLORER_TRANSACTION_PATH = "tx/";              //blockr.io path
    public static final String BLOCKEXPLORER_BLOCK_PATH = "block/";                 //blockr.io path
    public static final String BLOCKEXPLORER_BASE_URL_TEST = BLOCKEXPLORER_BASE_URL_PROD;

    public static final String DONATION_ADDRESS = "Mz1eQ1BA5tJqVpmnCbRyAExdEcwYpp7xyz";  //HashEngineering donation DGC address

    public static final String UNSPENT_API_URL = "http://bitcoin-abe.info/chain/Namecoin/unspent/";
    public enum UnspentAPIType {
        BitEasy,
        Blockr,
        Abe,
        Cryptoid,
    };
    public static final UnspentAPIType UnspentAPI = UnspentAPIType.Abe;

    enum CoinHash {
        SHA256,
        scrypt,
        other,
    };
    public static final CoinHash coinPOWHash = CoinHash.other;

    public static boolean checkpointFileSupport = true;
    public static int checkpointDaysBack = 21;

    public static final int TARGET_TIMESPAN = (int)(128 * 10 * 60);  // ~ 1 day per difficulty cycle, on average.
    public static final int TARGET_SPACING = (int)(10 * 60);  // 10 minutes per block.
    public static final int INTERVAL = TARGET_TIMESPAN / TARGET_SPACING;  //

    public static final int getIntervalCheckpoints() {
            return 2016;    //1080

    }
    public static int getFullRetargetStartBlock()
    {
        return 19200;
    }

    public static int spendableCoinbaseDepth = 100; //main.h: static const int CINBASE_MATURITY
    public static final int MAX_COINS = 20000000;                 //main.h:  MAX_MONEY


    public static final Coin DEFAULT_MIN_TX_FEE = Coin.valueOf(1000);   // MIN_TX_FEE
    public static final Coin DUST_LIMIT = Coin.valueOf(100); //main.h CTransaction::GetMinFee        0.01 coins

    public static final int PROTOCOL_VERSION = 70001;          //version.h PROTOCOL_VERSION
    public static final int MIN_PROTOCOL_VERSION = 60002;        //version.h MIN_PROTO_VERSION
    public static final int INIT_PROTO_VERSION = 209;            //version.h

    public static final int BLOCK_CURRENTVERSION = 1;   //CBlock::CURRENT_VERSION
    public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;


    public static final boolean supportsBloomFiltering = false; //Requires PROTOCOL_VERSION 70000 in the client
    public static boolean supportsIrcDiscovery() {
        return PROTOCOL_VERSION <= 70000;
    }

    public static final int Port    = 55889;       //protocol.h GetDefaultPort(testnet=false)
    public static final int TestPort = 45889;     //protocol.h GetDefaultPort(testnet=true)

    //
    //  Production
    //
    public static final int AddressHeader = 0;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS
    public static final int p2shHeader = 5;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS
    public static final boolean allowBitcoinPrivateKey = false; //for backward compatibility with previous version of digitalcoin
    public static final long PacketMagic = 0x5b6c44a4;      //0x5b, 0x6c, 0x44, 0xa4

    //Genesis Block Information from main.cpp: LoadBlockIndex
    static public long genesisBlockDifficultyTarget = (0x1d00ffffL);         //main.cpp: LoadBlockIndex
    static public long genesisBlockTime = 1426224182L;                       //main.cpp: LoadBlockIndex
    static public long genesisBlockNonce = (2558320123L);                         //main.cpp: LoadBlockIndex
    static public String genesisHash = "000000004f7ca0e7345a6c29b19a2d555fe922540adfdd74aeaa2cee98d52d85"; //main.cpp: hashGenesisBlock
    static public int genesisBlockValue = 50;
    static public int genesisBlockVersion = 1; //main.cpp: LoadBlockIndex
    //taken from the raw data of the block explorer
                                            //"04ff7f001c020a024b2e2e2e2063686f6f7365207768617420636f6d6573206e6578742e20204c69766573206f6620796f7572206f776e2c206f7220612072657475726e20746f20636861696e732e202d2d2056
    static public String genesisTxInBytes = "04ffff001d01044c4d4e592054696d65732031332f4d61722f323031352050726f647563657220507269636520496e6465782046616c6c732c20506f696e74696e6720746f204c6f77657220496e666c6174696f6e20";   //"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    static public String genesisTxOutBytes = "04b620369050cd899ffbbc4e8ee51e8c4534a855bb463439d63d235d4779685d8b6f4870a238cf365ac94fa13ef9a2a22cd99d0d5ee86dcabcafce36c7acf43ce5";
                                           //"4104b620369050cd899ffbbc4e8ee51e8c4534a855bb463439d63d235d4779685d8b6f4870a238cf365ac94fa13ef9a2a22cd99d0d5ee86dcabcafce36c7acf43ce5ac"


    //static public String genesisMerkleRoot = "3ce968df58f9c8a752306c4b7264afab93149dbc578bd08a42c446caaa6628bb";


    //net.cpp strDNSSeed
    static public String[] dnsSeeds = new String[] {
        "seed.winc-ev.de",
        "seed.winc-ev.com",
        "dnsseed.wlc-dnsseed.ssdpool.com"
    };

    public static int minBroadcastConnections = 1;   //0 for default; we need more peers.

    //
    // TestNet
    //
    public static final boolean supportsTestNet = false;
    public static final int testnetAddressHeader = 111;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS_TEST
    public static final int testnetp2shHeader = 196;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS_TEST
    public static final long testnetPacketMagic = 0xfabfb5da;      //0xfc, 0xc1, 0xb7, 0xdc
    public static final String testnetGenesisHash = "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008";
    static public long testnetGenesisBlockDifficultyTarget = (0x1d07fff8L);         //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockTime = 1296688602L;                       //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockNonce = (384568319);                         //main.cpp: LoadBlockIndex

    //main.cpp GetBlockValue(height, fee)
    public static final Coin GetBlockReward(int height)
    {
        int COIN = 1;
        Coin nSubsidy = Coin.valueOf(15, 0);



            //return nSubsidy.shiftRight(height / subsidyDecreaseBlockCount);
        return nSubsidy;
    }

    public static int subsidyDecreaseBlockCount = 2500;     //main.cpp GetBlockValue(height, fee)

    public static BigInteger proofOfWorkLimit = Utils.decodeCompactBits(0x1d00ffffL);  //main.cpp bnProofOfWorkLimit (~uint256(0) >> 20); // digitalcoin: starting difficulty is 1 / 2^12

    static public String[] testnetDnsSeeds = new String[] {
          "not supported"
    };
    //from main.h: CAlert::CheckSignature
    public static final String SATOSHI_KEY = "04EF014B36647E8433A2CEDF76F1D6EA0BC5914BA936FADCEDA90D7472DA3CF442469D3A1AB5EE416E7428726761DD3188BDA3D0AE163DB491F8CA0BDAD92A0506";
    public static final String TESTNET_SATOSHI_KEY = "04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a";

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_MAINNET = "org.worldleadcurrency.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_TESTNET = "org.worldleadcurrency.test";
    /** Unit test network. */
    public static final String ID_UNITTESTNET = "com.google.worldleadcurrency.unittest";

    //checkpoints.cpp Checkpoints::mapCheckpoints
    public static void initCheckpoints(Map<Integer, Sha256Hash> checkpoints)
    {
        checkpoints.put( 0, new Sha256Hash(CoinDefinition.genesisHash));
//        checkpoints.put( 28888, new Sha256Hash("00000000000228ce19f55cf0c45e04c7aa5a6a873ed23902b3654c3c49884502"));

    }

    //Unit Test Information
    public static final String UNITTEST_ADDRESS = "FmpNNw388tMqsDkKW6KfyksRkCVWqjBSCe";
    public static final String UNITTEST_ADDRESS_PRIVATE_KEY = "QU1rjHbrdJonVUgjT7Mncw7PEyPv3fMPvaGXp9EHDs1uzdJ98hUZ";

}
