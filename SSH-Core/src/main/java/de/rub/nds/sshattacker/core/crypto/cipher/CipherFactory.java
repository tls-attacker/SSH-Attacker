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
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static EncryptionCipher getEncryptionCipher(
            EncryptionAlgorithm encryptionAlgorithm,
            KeySet keySet,
            ConnectionEndType connectionEndType) {
        if (encryptionAlgorithm == EncryptionAlgorithm.NONE) {
            return new NoneCipher();
        } else if (encryptionAlgorithm.getJavaName() != null) {
            return new JavaCipher(
                    encryptionAlgorithm,
                    keySet.getWriteEncryptionKey(connectionEndType),
                    encryptionAlgorithm.getType() == EncryptionAlgorithmType.STREAM);
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
        if (encryptionAlgorithm == EncryptionAlgorithm.NONE) {
            return new NoneCipher();
        } else if (encryptionAlgorithm.getJavaName() != null) {
            return new JavaCipher(
                    encryptionAlgorithm,
                    keySet.getReadEncryptionKey(connectionEndType),
                    encryptionAlgorithm.getType() == EncryptionAlgorithmType.STREAM);
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
