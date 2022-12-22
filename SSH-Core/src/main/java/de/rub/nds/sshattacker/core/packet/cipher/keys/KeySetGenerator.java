/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher.keys;

import de.rub.nds.sshattacker.core.constants.KeyDerivationLabels;
import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class KeySetGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeySetGenerator() {}

    public static KeySet generateKeySet(SshContext context) {
        KeySet keySet = new KeySet();
        Chooser chooser = context.getChooser();
        String hashAlgorithm = chooser.getKeyExchangeAlgorithm().getDigest();
        byte[] sharedSecret = context.getSharedSecret().orElse(new byte[0]);
        byte[] exchangeHash = context.getExchangeHash().orElse(new byte[0]);
        byte[] sessionId = context.getSessionID().orElse(new byte[0]);

        keySet.setClientWriteInitialIv(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.INITIAL_IV_CLIENT_TO_SERVER,
                        sessionId,
                        chooser.getEncryptionAlgorithmClientToServer().getIVSize(),
                        hashAlgorithm));
        keySet.setServerWriteInitialIv(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.INITIAL_IV_SERVER_TO_CLIENT,
                        sessionId,
                        chooser.getEncryptionAlgorithmServerToClient().getIVSize(),
                        hashAlgorithm));
        keySet.setClientWriteEncryptionKey(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.ENCRYPTION_KEY_CLIENT_TO_SERVER,
                        sessionId,
                        chooser.getEncryptionAlgorithmClientToServer().getKeySize(),
                        hashAlgorithm));
        keySet.setServerWriteEncryptionKey(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.ENCRYPTION_KEY_SERVER_TO_CLIENT,
                        sessionId,
                        chooser.getEncryptionAlgorithmServerToClient().getKeySize(),
                        hashAlgorithm));
        keySet.setClientWriteIntegrityKey(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.INTEGRITY_KEY_CLIENT_TO_SERVER,
                        sessionId,
                        chooser.getMacAlgorithmClientToServer().getKeySize(),
                        hashAlgorithm));
        keySet.setServerWriteIntegrityKey(
                KeyDerivation.deriveKey(
                        sharedSecret,
                        exchangeHash,
                        KeyDerivationLabels.INTEGRITY_KEY_SERVER_TO_CLIENT,
                        sessionId,
                        chooser.getMacAlgorithmServerToClient().getKeySize(),
                        hashAlgorithm));

        LOGGER.info(keySet);
        return keySet;
    }
}
