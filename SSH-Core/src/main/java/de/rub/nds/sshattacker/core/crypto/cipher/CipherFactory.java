/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmFamily;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmType;
import de.rub.nds.sshattacker.core.constants.HashFunction;
import java.security.Key;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class CipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static AbstractCipher getCipher(EncryptionAlgorithm encryptionAlgorithm, byte[] key) {
        return getCipher(encryptionAlgorithm, key, true);
    }

    public static AbstractCipher getCipher(
            EncryptionAlgorithm encryptionAlgorithm, byte[] key, boolean mainCipher) {
        if (encryptionAlgorithm == EncryptionAlgorithm.NONE) {
            return new NoneCipher();
        } else if (mainCipher
                && encryptionAlgorithm.getFamily() == EncryptionAlgorithmFamily.CHACHA20_POLY1305) {
            // If mainCipher is not set, the factory will return a JavaCipher wrapping a ChaCha20
            // instance used for header encryption / decryption
            return new ChaCha20Poly1305Cipher(encryptionAlgorithm, key);
        } else if (encryptionAlgorithm.getJavaName() != null) {
            return new JavaCipher(
                    encryptionAlgorithm,
                    key,
                    encryptionAlgorithm.getType() == EncryptionAlgorithmType.STREAM);
        } else {
            LOGGER.warn(
                    "Encryption algorithm '{}' is not supported - Using NullCipher!",
                    encryptionAlgorithm);
            return new NoneCipher();
        }
    }

    public static AbstractCipher getOaepCipher(HashFunction hashFunction, Key key) {
        try {
            return new OaepCipher(
                    key,
                    "RSA/ECB/OAEPWith" + hashFunction.getJavaName() + "AndMGF1Padding",
                    hashFunction.getJavaName(),
                    "MGF1");
        } catch (Exception e) {
            LOGGER.warn(
                    "Cannot generate OAEP cipher for digest: '{}' - Using NoneCipher!",
                    hashFunction);
            return new NoneCipher();
        }
    }

    private CipherFactory() {
        super();
    }
}
