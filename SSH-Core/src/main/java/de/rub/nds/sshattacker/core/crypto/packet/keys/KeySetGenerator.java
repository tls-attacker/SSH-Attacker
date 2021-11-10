/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.packet.keys;

import de.rub.nds.sshattacker.core.constants.KeyDerivationLabels;
import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeySetGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static KeySet generateKeySet(SshContext context) {
        KeySet keySet = new KeySet();
        String hashAlgorithm =
                context.getKeyExchangeAlgorithm().orElseThrow(AdjustmentException::new).getDigest();
        KeyExchange keyExchange =
                context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);
        byte[] exchangeHash = context.getExchangeHashInstance().get();
        byte[] sessionId = context.getSessionID().orElseThrow(AdjustmentException::new);

        keySet.setClientWriteInitialIV(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        KeyDerivationLabels.INITIAL_IV_CLIENT_TO_SERVER,
                        sessionId,
                        context.getCipherAlgorithmClientToServer()
                                .orElseThrow(AdjustmentException::new)
                                .getBlockSize(),
                        hashAlgorithm));
        keySet.setServerWriteInitialIV(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        KeyDerivationLabels.INITIAL_IV_SERVER_TO_CLIENT,
                        sessionId,
                        context.getCipherAlgorithmServerToClient()
                                .orElseThrow(AdjustmentException::new)
                                .getBlockSize(),
                        hashAlgorithm));
        keySet.setClientWriteEncryptionKey(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        KeyDerivationLabels.ENCRYPTION_KEY_CLIENT_TO_SERVER,
                        sessionId,
                        context.getCipherAlgorithmClientToServer()
                                .orElseThrow(AdjustmentException::new)
                                .getKeySize(),
                        hashAlgorithm));
        keySet.setServerWriteEncryptionKey(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        KeyDerivationLabels.ENCRYPTION_KEY_SERVER_TO_CLIENT,
                        sessionId,
                        context.getCipherAlgorithmServerToClient()
                                .orElseThrow(AdjustmentException::new)
                                .getKeySize(),
                        hashAlgorithm));
        keySet.setClientWriteIntegrityKey(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        KeyDerivationLabels.INTEGRITY_KEY_CLIENT_TO_SERVER,
                        sessionId,
                        context.getMacAlgorithmClientToServer()
                                .orElseThrow(AdjustmentException::new)
                                .getKeySize(),
                        hashAlgorithm));
        keySet.setServerWriteIntegrityKey(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        KeyDerivationLabels.INTEGRITY_KEY_SERVER_TO_CLIENT,
                        sessionId,
                        context.getMacAlgorithmServerToClient()
                                .orElseThrow(AdjustmentException::new)
                                .getKeySize(),
                        hashAlgorithm));

        LOGGER.info(keySet);
        return keySet;
    }
}
