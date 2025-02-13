/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher.keys;

import de.rub.nds.sshattacker.core.constants.HashFunction;
import de.rub.nds.sshattacker.core.constants.KeyDerivationLabels;
import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class KeySetGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeySetGenerator() {
        super();
    }

    public static KeySet generateKeySet(SshContext context) {
        KeySet keySet = new KeySet();
        Chooser chooser = context.getChooser();
        HashFunction hashFunction = chooser.getKeyExchangeAlgorithm().getHashFunction();
        byte[] sharedSecret =
                Converter.bytesToLengthPrefixedBinaryString(
                        context.getSharedSecret().orElse(new byte[] {0}));
        byte[] exchangeHash = context.getExchangeHash().orElse(new byte[0]);
        byte[] sessionId = context.getSessionID().orElse(new byte[0]);

        keySet.setClientWriteInitialIv(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.INITIAL_IV_CLIENT_TO_SERVER,
                        sessionId,
                        chooser.getEncryptionAlgorithmClientToServer().getIVSize(),
                        hashFunction));
        keySet.setServerWriteInitialIv(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.INITIAL_IV_SERVER_TO_CLIENT,
                        sessionId,
                        chooser.getEncryptionAlgorithmServerToClient().getIVSize(),
                        hashFunction));
        keySet.setClientWriteEncryptionKey(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.ENCRYPTION_KEY_CLIENT_TO_SERVER,
                        sessionId,
                        chooser.getEncryptionAlgorithmClientToServer().getKeySize(),
                        hashFunction));
        keySet.setServerWriteEncryptionKey(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.ENCRYPTION_KEY_SERVER_TO_CLIENT,
                        sessionId,
                        chooser.getEncryptionAlgorithmServerToClient().getKeySize(),
                        hashFunction));
        keySet.setClientWriteIntegrityKey(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.INTEGRITY_KEY_CLIENT_TO_SERVER,
                        sessionId,
                        chooser.getMacAlgorithmClientToServer().getKeySize(),
                        hashFunction));
        keySet.setServerWriteIntegrityKey(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.INTEGRITY_KEY_SERVER_TO_CLIENT,
                        sessionId,
                        chooser.getMacAlgorithmServerToClient().getKeySize(),
                        hashFunction));

        LOGGER.info(keySet);
        return keySet;
    }
}
