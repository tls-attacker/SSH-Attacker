/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.oracles;

import de.rub.nds.tlsattacker.util.MathHelper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * A mock Manger oracle that used a private key to decrypt the messages and answers if the message
 * is PKCS1 conform
 */
public class MockOracle extends Pkcs1Oracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final RSAPrivateKey privateKey;
    private final Cipher cipher;

    public MockOracle(RSAPublicKey publicKey, RSAPrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.blockSize = MathHelper.intCeilDiv(publicKey.getModulus().bitLength(), Byte.SIZE);

        // Init cipher
        this.cipher = Cipher.getInstance("RSA/NONE/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    @Override
    public boolean checkPKCSConformity(byte[] msg) {
        if (isPlaintextOracle) {
            return msg[0] == (byte) 0;
        } else {
            try {
                byte[] decryptedMessage = cipher.doFinal(msg);

                // Cipher decrypts message and automatically cuts off starting 00 bytes.
                // Correct messages therefore should consist of fewer bytes than the length of the
                // public key
                int pKeyLen = privateKey.getModulus().bitLength() / Byte.SIZE;
                return decryptedMessage.length != pKeyLen;

            } catch (IllegalBlockSizeException | BadPaddingException e) {
                LOGGER.error("Decryption error", e);
                return false;
            }
        }
    }
}
