/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.oracles;

import de.rub.nds.sshattacker.attacks.pkcs1.OracleException;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.tlsattacker.util.MathHelper;
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

    /**
     * Check the given content for PKCS-Conformity which double encryption.
     *
     * @param msg Encrypted message to check for conformity
     * @return An Array for both encryption, the first entry for the outer-encryption, the second
     *     for the inner encryption
     */
    @Override
    public boolean[] checkDoublePKCSConformity(byte[] msg) {

        boolean[] oracleResult = new boolean[] {false, false};
        counter++;
        if (counter % 500 == 0) {
            LOGGER.info("[{}] Tries", counter);
        }
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

                byte[] firstStep = null;
                byte[] secondStep = null;

                if (hostPublicKey.getModulus().bitLength()
                        > serverPublicKey.getModulus().bitLength()) {
                    this.cipher.init(Cipher.DECRYPT_MODE, hostPriv);
                    firstStep = cipher.doFinal(msg);

                    oracleResult[0] = true;

                    this.cipher.init(Cipher.DECRYPT_MODE, serverPriv);
                    secondStep = cipher.doFinal(firstStep);

                    oracleResult[1] = true;

                } else {
                    this.cipher.init(Cipher.DECRYPT_MODE, serverPriv);
                    firstStep = cipher.doFinal(msg);

                    oracleResult[0] = true;

                    this.cipher.init(Cipher.DECRYPT_MODE, hostPriv);
                    secondStep = cipher.doFinal(firstStep);

                    oracleResult[1] = true;
                }

                LOGGER.debug(secondStep);

                return oracleResult;

            } catch (IllegalBlockSizeException | BadPaddingException e) {
                // LOGGER.error("Decryption error", e);
                return oracleResult;
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
