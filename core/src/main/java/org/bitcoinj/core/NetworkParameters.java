/**
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import org.bitcoinj.params.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptOpCodes;
import com.google.common.base.Objects;
import org.spongycastle.util.encoders.Hex;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.*;

import static org.bitcoinj.core.Coin.*;

/**
 * <p>NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.</p>
 *
 * <p>This is an abstract class, concrete instantiations can be found in the params package. There are four:
 * one for the main network ({@link MainNetParams}), one for the public test network, and two others that are
 * intended for unit testing and local app development purposes. Although this class contains some aliases for
 * them, you are encouraged to call the static get() methods on each specific params class directly.</p>
 */
public abstract class NetworkParameters implements Serializable {
    /**
     * The protocol version this library implements.
     */
    public static final int PROTOCOL_VERSION = CoinDefinition.PROTOCOL_VERSION;

    /**
     * The alert signing key originally owned by Satoshi, and now passed on to Gavin along with a few others.
     */

    public static final byte[] SATOSHI_KEY = Hex.decode(CoinDefinition.SATOSHI_KEY); //Hex.decode("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_MAINNET = CoinDefinition.ID_MAINNET; //"org.bitcoin.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_TESTNET = CoinDefinition.ID_TESTNET; //"org.bitcoin.test";
    /** Unit test network. */
    public static final String ID_UNITTESTNET = CoinDefinition.ID_UNITTESTNET; //"com.google.bitcoin.unittest";

    public static final String ID_REGTEST = ID_TESTNET + "reg";

    /** The string used by the payment protocol to represent the main net. */
    public static final String PAYMENT_PROTOCOL_ID_MAINNET = "main";
    /** The string used by the payment protocol to represent the test net. */
    public static final String PAYMENT_PROTOCOL_ID_TESTNET = "test";

    // TODO: Seed nodes should be here as well.

    protected Block genesisBlock;
    protected BigInteger maxTarget;
    protected int port;
    protected long packetMagic;  // Indicates message origin network and is used to seek to the next message when stream state is unknown.
    protected int addressHeader;
    protected int p2shHeader;
    protected int dumpedPrivateKeyHeader;
    protected int interval;
    protected int targetTimespan;
    protected byte[] alertSigningKey;

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    protected String id;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    protected int spendableCoinbaseDepth;
    protected int subsidyDecreaseBlockCount;
    
    protected int[] acceptableAddressCodes;
    protected String[] dnsSeeds;
    protected Map<Integer, Sha256Hash> checkpoints = new HashMap<Integer, Sha256Hash>();

    protected NetworkParameters() {
        alertSigningKey = SATOSHI_KEY;
        genesisBlock = createGenesis(this);
    }
    //TODO:  put these bytes into the CoinDefinition
    private static Block createGenesis(NetworkParameters n) {
        Block genesisBlock = new Block(n);
        //genesisBlock.setVersion(CoinDefinition.genesisBlockVersion);
        Transaction t = new Transaction(n);
        try {
            // A script containing the difficulty bits and the following message:
            //

            //   coin dependent
            byte[] bytes = Hex.decode(CoinDefinition.genesisTxInBytes);
            //byte[] bytes = Hex.decode("04ffff001d0104294469676974616c636f696e2c20412043757272656e637920666f722061204469676974616c20416765");
            t.setRefHeight(0);
            t.addInput(new TransactionInput(n, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            //Adding Worldleadcurrency genesisblock
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, SATOSHI.multiply(25453671561), scriptPubKeyBytes.toByteArray()));

            scriptPubKeyBytes.reset();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("5029d180e0c5ed798d877b1ada99772986c1422ca932c41b2d04000000000000"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            Script.writeBytes(scriptPubKeyBytes,new byte[] {(byte) 0}); 
            t.addOutput(new TransactionOutput(n, t, SATOSHI.multiply(1), scriptPubKeyBytes.toByteArray()));

            scriptPubKeyBytes.reset();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("202020"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("4d6574616c73207765726520616e20696d706c696369746c7920616275736976652061677265656d656e742e0a4d6f6465726e2022706170657222206973206120666c6177656420746f6f6c2c2069747320656e67696e656572696e672069732061206e657374206f66206c6565636865732e0a546865206f6c64206d6f6e6579206973206f62736f6c6574652e0a4c65742074686520696e646976696475616c206d6f6e6574697a65206974732063726564697420776974686f75742063617274656c20696e7465726d65646961726965732e0a4769766520757320612072656e742d6c657373206361736820736f2077652063616e206265206672656520666f72207468652066697273742074696d652e0a4c65742074686973206265207468652061776169746564206461776e2e"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DUP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_HASH160);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("0ef0f9d19a653023554146a866238b8822bc84df"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_EQUALVERIFY);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, SATOSHI.multiply(1), scriptPubKeyBytes.toByteArray()));

            scriptPubKeyBytes.reset();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("2020202020202020"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("224c65742075732063616c63756c6174652c20776974686f757420667572746865722061646f2c20696e206f7264657220746f207365652077686f2069732072696768742e22202d2d476f747466726965642057696c68656c6d204c6569626e697a0acebec2b4efbda5e28880efbda560efbc89e38080e38080e38080e3808020206e0aefbfa3e38080e38080e380802020efbcbce38080e380802020efbc882045efbc8920676f6f64206a6f622c206d61616b75210aefbe8ce38080e38080e3808020202fe383bd20e383bd5fefbc8fefbc8f"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DUP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_HASH160);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("c26be5ec809aa4bf6b30aa89823cff7cedc3679a"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_EQUALVERIFY);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, SATOSHI.multiply(1), scriptPubKeyBytes.toByteArray()));

            scriptPubKeyBytes.reset();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("202020202020"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("4963682077c3bc6e7363686520574c43207669656c204572666f6c67207a756d204e75747a656e206465722039392050726f7a656e7421"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DUP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_HASH160);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("2939acd60037281a708eb11e4e9eda452c029eca"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_EQUALVERIFY);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, SATOSHI.multiply(1), scriptPubKeyBytes.toByteArray()));

            scriptPubKeyBytes.reset();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("20202020202020202020202020"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("225468652076616c7565206f662061206d616e2073686f756c64206265207365656e20696e207768617420686520676976657320616e64206e6f7420696e20776861742068652069732061626c6520746f20726563656976652e22202d2d416c626572742045696e737465696e"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DUP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_HASH160);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("f9ca5caab4bda4dc28b5556aa79a2eec0447f0bf"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_EQUALVERIFY);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, SATOSHI.multiply(1), scriptPubKeyBytes.toByteArray()));

            scriptPubKeyBytes.reset();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("20202020202020202020202020"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("22416e2061726d79206f66207072696e6369706c65732063616e2070656e65747261746520776865726520616e2061726d79206f6620736f6c64696572732063616e6e6f742e22202d2d54686f6d6173205061696e65"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DROP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DUP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_HASH160);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("08f320cbb41a1ae25b794f6175f96080681989f3"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_EQUALVERIFY);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, SATOSHI.multiply(1), scriptPubKeyBytes.toByteArray()));

            scriptPubKeyBytes.reset();
            scriptPubKeyBytes.write(ScriptOpCodes.OP_DUP);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_HASH160);
            Script.writeBytes(scriptPubKeyBytes, Hex.decode("85e54144c4020a65fa0a8fdbac8bba75dbc2fd00"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_EQUALVERIFY);
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, SATOSHI.multiply(49603174604), scriptPubKeyBytes.toByteArray())); 

        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        genesisBlock.addTransaction(t);
        genesisBlock.setMerkleRoot(new Sha256Hash("e399be31d62cef5791bd0f944e3a291fb4b22cf5c6528835ce60922977722785"));
        return genesisBlock;
    }




    public static final int TARGET_TIMESPAN = CoinDefinition.TARGET_TIMESPAN;//128 * 60;  // 2 weeks per difficulty cycle, on average.
    public static final int TARGET_SPACING = CoinDefinition.TARGET_SPACING;// 10 * 60;  // 10 minutes per block.
    public static final int INTERVAL = CoinDefinition.INTERVAL;//TARGET_TIMESPAN / TARGET_SPACING;
    
    /**
     * Blocks with a timestamp after this should enforce BIP 16, aka "Pay to script hash". This BIP changed the
     * network rules in a soft-forking manner, that is, blocks that don't follow the rules are accepted but not
     * mined upon and thus will be quickly re-orged out as long as the majority are enforcing the rule.
     */
    public static final int BIP16_ENFORCE_TIME = 1333238400;
    
    /**
     * The maximum number of coins to be generated
     */
    public static final long MAX_COINS = CoinDefinition.MAX_COINS;

    /**
     * The maximum money to be generated
     */

    public static final Coin MAX_MONEY = COIN.multiply(CoinDefinition.MAX_COINS);


    /** Alias for TestNet3Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet() {
        return TestNet3Params.get();
    }

    /** Alias for TestNet2Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet2() {
        return TestNet2Params.get();
    }

    /** Alias for TestNet3Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet3() {
        return TestNet3Params.get();
    }

    /** Alias for MainNetParams.get(), use that instead */
    @Deprecated
    public static NetworkParameters prodNet() {
        return MainNetParams.get();
    }

    /** Returns a testnet params modified to allow any difficulty target. */
    @Deprecated
    public static NetworkParameters unitTests() {
        return UnitTestParams.get();
    }

    /** Returns a standard regression test params (similar to unitTests) */
    @Deprecated
    public static NetworkParameters regTests() {
        return RegTestParams.get();
    }

    /**
     * A Java package style string acting as unique ID for these parameters
     */
    public String getId() {
        return id;
    }

    public abstract String getPaymentProtocolId();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkParameters other = (NetworkParameters) o;
        return getId().equals(other.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getId());
    }

    /** Returns the network parameters for the given string ID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromID(String id) {
        if (id.equals(ID_MAINNET)) {
            return MainNetParams.get();
        } else if (id.equals(ID_TESTNET)) {
            return TestNet3Params.get();
        } else if (id.equals(ID_UNITTESTNET)) {
            return UnitTestParams.get();
        } else if (id.equals(ID_REGTEST)) {
            return RegTestParams.get();
        } else {
            return null;
        }
    }

    /** Returns the network parameters for the given string paymentProtocolID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromPmtProtocolID(String pmtProtocolId) {
        if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_MAINNET)) {
            return MainNetParams.get();
        } else if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_TESTNET)) {
            return TestNet3Params.get();
        } else {
            return null;
        }
    }

    public int getSpendableCoinbaseDepth() {
        return spendableCoinbaseDepth;
    }

    /**
     * Returns true if the block height is either not a checkpoint, or is a checkpoint and the hash matches.
     */
    public boolean passesCheckpoint(int height, Sha256Hash hash) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash == null || checkpointHash.equals(hash);
    }

    /**
     * Returns true if the given height has a recorded checkpoint.
     */
    public boolean isCheckpoint(int height) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash != null;
    }

    public int getSubsidyDecreaseBlockCount() {
        return subsidyDecreaseBlockCount;
    }

    /** Returns DNS names that when resolved, give IP addresses of active peers. */
    public String[] getDnsSeeds() {
        return dnsSeeds;
    }

    /**
     * <p>Genesis block for this chain.</p>
     *
     * <p>The first block in every chain is a well known constant shared between all Bitcoin implemenetations. For a
     * block to be valid, it must be eventually possible to work backwards to the genesis block by following the
     * prevBlockHash pointers in the block headers.</p>
     *
     * <p>The genesis blocks for both test and prod networks contain the timestamp of when they were created,
     * and a message in the coinbase transaction. It says, <i>"The Times 03/Jan/2009 Chancellor on brink of second
     * bailout for banks"</i>.</p>
     */
    public Block getGenesisBlock() {
        return genesisBlock;
    }

    /** Default TCP port on which to connect to nodes. */
    public int getPort() {
        return port;
    }

    /** The header bytes that identify the start of a packet on this network. */
    public long getPacketMagic() {
        return packetMagic;
    }

    /**
     * First byte of a base58 encoded address. See {@link org.bitcoinj.core.Address}. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     */
    public int getAddressHeader() {
        return addressHeader;
    }

    /**
     * First byte of a base58 encoded P2SH address.  P2SH addresses are defined as part of BIP0013.
     */
    public int getP2SHHeader() {
        return p2shHeader;
    }

    /** First byte of a base58 encoded dumped private key. See {@link org.bitcoinj.core.DumpedPrivateKey}. */
    public int getDumpedPrivateKeyHeader() {
        return dumpedPrivateKeyHeader;
    }

    /**
     * How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
     * significantly different from this value, the network difficulty formula will produce a different value. Both
     * test and production Bitcoin networks use 2 weeks (1209600 seconds).
     */
    public int getTargetTimespan() {
        return targetTimespan;
    }

    /**
     * The version codes that prefix addresses which are acceptable on this network. Although Satoshi intended these to
     * be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the
     * address and to prevent accidentally sending coins across chains which would destroy them.
     */
    public int[] getAcceptableAddressCodes() {
        return acceptableAddressCodes;
    }

    /**
     * If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks.
     */
    public boolean allowEmptyPeerChain() {
        return true;
    }

    /** How many blocks pass between difficulty adjustment periods. Bitcoin standardises this to be 2015. */
    public int getInterval() {
        return interval;
    }

    /** Maximum target represents the easiest allowable proof of work. */
    public BigInteger getMaxTarget() {
        return maxTarget;
    }

    /**
     * The key used to sign {@link org.bitcoinj.core.AlertMessage}s. You can use {@link org.bitcoinj.core.ECKey#verify(byte[], byte[], byte[])} to verify
     * signatures using it.
     */
    public byte[] getAlertSigningKey() {
        return alertSigningKey;
    }
}
