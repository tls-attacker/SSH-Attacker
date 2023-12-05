/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.oracles;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.pkcs1.OracleException;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.tlsattacker.util.MathHelper;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A mock Manger oracle that used a private key to decrypt the messages and answers if the message
 * is PKCS1 conform
 */
public class Ssh1MockOracle extends Pkcs1Oracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final RSAPrivateKey hostPrivateKey;
    private final RSAPrivateKey serverPrivateKey;
    private final RSAPublicKey hostPublicKey;
    private final RSAPublicKey serverPublicKey;
    private final Cipher cipher;

    public Ssh1MockOracle(
            CustomRsaPublicKey hostPublicKey,
            CustomRsaPrivateKey hostPrivateKey,
            CustomRsaPublicKey serverPublicKey,
            CustomRsaPrivateKey serverPrivateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.hostPublicKey = hostPublicKey;
        this.hostPrivateKey = hostPrivateKey;
        this.serverPublicKey = serverPublicKey;
        this.serverPrivateKey = serverPrivateKey;
        this.blockSize = MathHelper.intCeilDiv(hostPublicKey.getModulus().bitLength(), Byte.SIZE);

        // Init cipher
        this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    int counter = 0;
    long timeElapsed = 0;

    /**
     * Check the given content for PKCS-Conformity
     *
     * @param msg Encrypted message to check for conformity
     * @return true, if conforming, false if not.
     * @throws OracleException
     */
    @Override
    public boolean checkPKCSConformity(byte[] msg) throws OracleException {
        return checkDoublePKCSConformity(msg)[0];
    }

    private boolean[] oracleStrong(byte[] msg) {

        boolean[] oracleResult = new boolean[] {false, false};
        counter++;
        if (counter % 500 == 0) {
            LOGGER.info(
                    String.format(
                            "[%d] Tries, took per average %f ms per oracle-request, in total %s ms have gone by",
                            counter, (timeElapsed / (double) counter), timeElapsed),
                    counter,
                    (timeElapsed / counter),
                    timeElapsed);
        }
        if (isPlaintextOracle) {
            return new boolean[] {true, true};
        } else {
            long start = System.currentTimeMillis();
            if (hostPublicKey.getModulus().bitLength() > serverPublicKey.getModulus().bitLength()) {

                byte[] decrypted_byte = decryptMessage(msg, hostPrivateKey);

                if (decrypted_byte[0] == 0x00 && decrypted_byte[1] == 0x02) {
                    oracleResult[0] = true;
                }

                if (oracleResult[0]) {
                    byte[] plainInput = removePCKS1Padding(decrypted_byte);
                    byte[] decryptedInner = decryptMessage(plainInput, serverPrivateKey);
                    if (decryptedInner[0] == 0x00 && decryptedInner[1] == 0x02) {
                        oracleResult[1] = true;
                    }
                }

            } else {

                byte[] decrypted_byte = decryptMessage(msg, serverPrivateKey);

                if (decrypted_byte[0] == 0x00 && decrypted_byte[1] == 0x02) {
                    oracleResult[0] = true;
                }

                if (oracleResult[0]) {
                    byte[] plainInput = removePCKS1Padding(decrypted_byte);
                    byte[] decryptedInner = decryptMessage(plainInput, hostPrivateKey);
                    if (decryptedInner[0] == 0x00 && decryptedInner[1] == 0x02) {
                        oracleResult[1] = true;
                    }
                }
            }

            long finish = System.currentTimeMillis();
            timeElapsed = timeElapsed + (finish - start);

            return oracleResult;
        }
    }

    private boolean[] oracleWeak(byte[] msg) {
        boolean[] oracleResult = new boolean[] {false, false};
        counter++;
        if (counter % 500 == 0) {
            LOGGER.info(
                    String.format(
                            "[%d] Tries, took per average %f ms per oracle-request, in total %s ms have gone by ",
                            counter, (timeElapsed / (double) counter), timeElapsed),
                    counter,
                    (timeElapsed / counter),
                    timeElapsed);
        }
        long start = System.currentTimeMillis();

        if (isPlaintextOracle) {
            return new boolean[] {true, true};
        } else {
            try {
                KeyFactory factory = KeyFactory.getInstance("RSA");
                RSAPrivateKey hostPriv =
                        (RSAPrivateKey)
                                factory.generatePrivate(
                                        new RSAPrivateKeySpec(
                                                hostPrivateKey.getModulus(),
                                                hostPrivateKey.getPrivateExponent()));
                RSAPrivateKey serverPriv =
                        (RSAPrivateKey)
                                factory.generatePrivate(
                                        new RSAPrivateKeySpec(
                                                serverPrivateKey.getModulus(),
                                                serverPrivateKey.getPrivateExponent()));

                byte[] firstStep;

                if (hostPublicKey.getModulus().bitLength()
                        > serverPublicKey.getModulus().bitLength()) {

                    this.cipher.init(Cipher.DECRYPT_MODE, hostPriv);
                    firstStep = cipher.doFinal(msg);

                    oracleResult[0] = true;

                    this.cipher.init(Cipher.DECRYPT_MODE, serverPriv);
                    cipher.doFinal(firstStep);

                    oracleResult[1] = true;

                } else {
                    this.cipher.init(Cipher.DECRYPT_MODE, serverPriv);
                    firstStep = cipher.doFinal(msg);

                    oracleResult[0] = true;

                    this.cipher.init(Cipher.DECRYPT_MODE, hostPriv);
                    cipher.doFinal(firstStep);

                    oracleResult[1] = true;
                }
                long finish = System.currentTimeMillis();
                timeElapsed = timeElapsed + (finish - start);
                return oracleResult;

            } catch (IllegalBlockSizeException | BadPaddingException e) {
                long finish = System.currentTimeMillis();
                timeElapsed = timeElapsed + (finish - start);

                return oracleResult;
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Check the given content for PKCS-Conformity which double encryption.
     *
     * @param msg Encrypted message to check for conformity
     * @return An Array for both encryption, the first entry for the outer-encryption, the second
     *     for the inner encryption
     */
    @Override
    public boolean[] checkDoublePKCSConformity(byte[] msg) {
        // return oracleWeak(msg);
        return oracleStrong(msg);
    }

    private byte[] fillUpArray(int lenght, byte[] inputArray) {
        byte[] tmp = new byte[inputArray.length];
        System.arraycopy(inputArray, 0, tmp, 0, inputArray.length);
        byte[] returnArray = new byte[lenght];
        System.arraycopy(tmp, 0, returnArray, lenght - tmp.length, tmp.length);
        return returnArray;
    }

    private byte[] decryptMessage(byte[] msg, RSAPrivateKey key) {
        BigInteger msg_bigint = new BigInteger(1, msg);
        BigInteger decrypted_msg = msg_bigint.modPow(key.getPrivateExponent(), key.getModulus());
        byte[] decrypted_byte = ArrayConverter.bigIntegerToByteArray(decrypted_msg);
        int k = key.getModulus().bitLength() / 8;

        if (decrypted_byte.length < k) {
            decrypted_byte = fillUpArray(k, decrypted_byte);
        }
        return decrypted_byte;
    }

    private byte[] removePCKS1Padding(byte[] input) {
        byte[] tmp_copy = new byte[input.length - 2];
        System.arraycopy(input, 2, tmp_copy, 0, tmp_copy.length);
        int idx = 0;
        for (int i = 0; i < tmp_copy.length; i++) {
            if (tmp_copy[i] == 0x00) {
                idx = i;
                break;
            }
        }

        idx = idx + 1; // +1 to skip 0 too
        byte[] result = new byte[tmp_copy.length - idx];
        System.arraycopy(tmp_copy, idx, result, 0, tmp_copy.length - idx);
        return result;
    }
}
