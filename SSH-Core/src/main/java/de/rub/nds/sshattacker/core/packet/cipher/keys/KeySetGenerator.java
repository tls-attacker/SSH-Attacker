/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher.keys;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyDerivationLabels;
import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.constant.LayerType;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class KeySetGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeySetGenerator() {}

    public static AbstractKeySet generateKeySet(SshContext context) {
        AbstractKeySet keySet;

        LayerType highestLayer =
                context.getContext().getLayerStack().getHighestLayer().getLayerType();
        if (highestLayer.equals(ImplementedLayers.SSHV2)) {
            keySet = new SSHv2KeySet();
            Chooser chooser = context.getChooser();
            String hashAlgorithm = chooser.getKeyExchangeAlgorithm().getDigest();
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
        } else if (highestLayer.equals(ImplementedLayers.SSHV1)) {
            keySet = new SSHv1KeySet();
            byte[] sharedSecret = context.getSharedSecret().orElse(new byte[] {0});

            if (context.getEncryptionAlgorithmClientToServer().isPresent()
                    && context.getEncryptionAlgorithmServerToClient().isPresent()) {

                EncryptionAlgorithm c2s, s2c;

                c2s = context.getEncryptionAlgorithmClientToServer().get();
                s2c = context.getEncryptionAlgorithmServerToClient().get();

                byte[] server_key;
                byte[] client_key;

                // Only DES, RC4, Blowfish and Triple DES are implemented now; Setting Key-Lenghtes
                // accordingly
                // Missing TSS and IDEA (CFB)
                if (c2s == EncryptionAlgorithm.TRIPLE_DES_CBC
                        && s2c == EncryptionAlgorithm.TRIPLE_DES_CBC) {
                    server_key = Arrays.copyOfRange(sharedSecret, 0, 24);
                    client_key = Arrays.copyOfRange(sharedSecret, 0, 24);

                    LOGGER.debug(
                            "SHARED SECRET is {}", ArrayConverter.bytesToHexString(server_key));

                } else if (c2s == EncryptionAlgorithm.DES_CBC
                        && s2c == EncryptionAlgorithm.DES_CBC) {
                    server_key = Arrays.copyOfRange(sharedSecret, 0, 8);
                    client_key = Arrays.copyOfRange(sharedSecret, 0, 8);

                    LOGGER.debug(
                            "SHARED SECRET is {}", ArrayConverter.bytesToHexString(server_key));

                } else if (c2s == EncryptionAlgorithm.BLOWFISH_CBC
                        && s2c == EncryptionAlgorithm.BLOWFISH_CBC) {
                    server_key = Arrays.copyOfRange(sharedSecret, 0, 32);
                    client_key = Arrays.copyOfRange(sharedSecret, 0, 32);

                    LOGGER.debug(
                            "SHARED SECRET is {}", ArrayConverter.bytesToHexString(server_key));

                } else if (c2s == EncryptionAlgorithm.ARCFOUR128
                        && s2c == EncryptionAlgorithm.ARCFOUR128) {
                    server_key = Arrays.copyOfRange(sharedSecret, 0, 16);
                    client_key = Arrays.copyOfRange(sharedSecret, 16, 32);

                    LOGGER.debug(
                            "Key Server 2 Client is {}",
                            ArrayConverter.bytesToHexString(server_key));
                    LOGGER.debug(
                            "Key Client 2 Server is {}",
                            ArrayConverter.bytesToHexString(client_key));

                } else {
                    server_key = sharedSecret;
                    client_key = sharedSecret;
                }

                keySet.setServerWriteEncryptionKey(server_key);
                keySet.setClientWriteEncryptionKey(client_key);
                keySet.setClientWriteInitialIv(new byte[c2s.getIVSize()]);
                keySet.setServerWriteInitialIv(new byte[s2c.getIVSize()]);
                LOGGER.debug("Generated SSHv1 Keyset sucessfully");
            } else {
                LOGGER.warn(
                        "Missing EncryptionAlgorithm for {}",
                        context.getEncryptionAlgorithmClientToServer().isPresent()
                                ? "Server!"
                                : "Client!");
            }

        } else {
            LOGGER.warn(
                    "Highest Layer {} not supported for Key Generation",
                    context.getContext()
                            .getLayerStack()
                            .getHighestLayer()
                            .getLayerType()
                            .getName());
            return null;
        }

        return keySet;
    }
}
