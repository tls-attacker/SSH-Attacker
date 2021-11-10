/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmType;
import de.rub.nds.sshattacker.core.crypto.packet.keys.KeySet;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static EncryptionCipher getEncryptionCipher(
            EncryptionAlgorithm encryptionAlgorithm,
            KeySet keySet,
            ConnectionEndType connectionEndType) {
        if (encryptionAlgorithm.getJavaName() != null) {
            try {
                return new JavaCipher(
                        encryptionAlgorithm,
                        keySet.getWriteEncryptionKey(connectionEndType),
                        keySet.getWriteIv(connectionEndType));
            } catch (CryptoException e) {
                LOGGER.warn(
                        "Caught a CryptoException while instantiating JavaCipher - Using NoneCipher!",
                        e);
                return new NoneCipher();
            }
        } else if (encryptionAlgorithm == EncryptionAlgorithm.NONE) {
            return new NoneCipher();
        } else {
            LOGGER.warn(
                    "Encryption algorithm '"
                            + encryptionAlgorithm
                            + "' is not supported - Using NullCipher!");
            return new NoneCipher();
        }
    }

    public static DecryptionCipher getDecryptionCipher(
            EncryptionAlgorithm encryptionAlgorithm,
            KeySet keySet,
            ConnectionEndType connectionEndType) {
        if (encryptionAlgorithm.getJavaName() != null) {
            try {
                if (encryptionAlgorithm.getType() == EncryptionAlgorithmType.STREAM) {
                    // No IV / tag length required
                    return new JavaCipher(
                            encryptionAlgorithm, keySet.getReadEncryptionKey(connectionEndType));
                } else if (encryptionAlgorithm.getType() == EncryptionAlgorithmType.AEAD) {
                    // IV and tag length required
                    return new JavaCipher(
                            encryptionAlgorithm,
                            keySet.getReadEncryptionKey(connectionEndType),
                            keySet.getReadIv(connectionEndType));
                } else {
                    // IV only
                    return new JavaCipher(
                            encryptionAlgorithm,
                            keySet.getReadEncryptionKey(connectionEndType),
                            keySet.getReadIv(connectionEndType));
                }
            } catch (CryptoException e) {
                LOGGER.warn(
                        "Caught a CryptoException while instantiating JavaCipher - Using NoneCipher!",
                        e);
                return new NoneCipher();
            }
        } else if (encryptionAlgorithm == EncryptionAlgorithm.NONE) {
            return new NoneCipher();
        } else {
            LOGGER.warn(
                    "Encryption algorithm '"
                            + encryptionAlgorithm
                            + "' is not supported - Using NullCipher!");
            return new NoneCipher();
        }
    }

    private CipherFactory() {}
}
