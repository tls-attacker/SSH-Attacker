/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmType;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import java.security.Key;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static AbstractCipher getCipher(EncryptionAlgorithm encryptionAlgorithm, byte[] key) {
        return getCipher(encryptionAlgorithm, key, true);
    }

    public static AbstractCipher getCipher(
            EncryptionAlgorithm encryptionAlgorithm, byte[] key, boolean mainCipher) {
        if (encryptionAlgorithm == EncryptionAlgorithm.NONE) {
            return new NoneCipher();
        } else if (mainCipher
                && encryptionAlgorithm == EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM) {
            // If mainCipher is not set, the factory will return a JavaCipher wrapping a ChaCha20
            // instance used for header encryption / decryption
            return new ChaCha20Poly1305Cipher(key);
        } else if (encryptionAlgorithm.getJavaName() != null) {
            return new JavaCipher(
                    encryptionAlgorithm,
                    key,
                    encryptionAlgorithm.getType() == EncryptionAlgorithmType.STREAM);
        } else {
            LOGGER.warn(
                    "Encryption algorithm '"
                            + encryptionAlgorithm
                            + "' is not supported - Using NullCipher!");
            return new NoneCipher();
        }
    }

    public static AbstractCipher getOaepCipher(KeyExchangeAlgorithm keyExchangeAlgorithm, Key key) {
        switch (keyExchangeAlgorithm) {
            case RSA1024_SHA1:
                return new OaepCipher(key, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "SHA-1", "MGF1");
            case RSA2048_SHA256:
                return new OaepCipher(
                        key, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "SHA-256", "MGF1");
            default:
                LOGGER.warn(
                        "Cannot generate OAEP cipher for key exchange algorithm: '"
                                + keyExchangeAlgorithm
                                + "' - Using NoneCipher!");
                return new NoneCipher();
        }
    }

    private CipherFactory() {}
}
