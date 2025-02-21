/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewKeysMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Objects;
import java.util.Optional;

public class NewKeysMessageHandler extends SshMessageHandler<NewKeysMessage>
        implements MessageSentHandler<NewKeysMessage> {

    @Override
    public void adjustContext(SshContext context, NewKeysMessage object) {
        ConnectionDirection enableEncryptionOnNewKeysMessage =
                context.getConfig().getEnableEncryptionOnNewKeysMessage();
        if (enableEncryptionOnNewKeysMessage == ConnectionDirection.BOTH
                || enableEncryptionOnNewKeysMessage == ConnectionDirection.RECEIVE) {
            adjustEncryptionForDirection(true, context);
            if (context.getStrictKeyExchangeEnabled().orElse(false)) {
                LOGGER.info("Resetting read sequence number to 0 because of strict key exchange");
                context.setReadSequenceNumber(0);
            }
        }
        adjustCompressionForDirection(true, context);
    }

    @Override
    public void adjustContextAfterMessageSent(SshContext context, NewKeysMessage object) {
        ConnectionDirection enableEncryptionOnNewKeysMessageType =
                context.getConfig().getEnableEncryptionOnNewKeysMessage();
        if (enableEncryptionOnNewKeysMessageType == ConnectionDirection.BOTH
                || enableEncryptionOnNewKeysMessageType == ConnectionDirection.SEND) {
            adjustEncryptionForDirection(false, context);
            if (context.getStrictKeyExchangeEnabled().orElse(false)) {
                LOGGER.info("Resetting write sequence number to 0 because of strict key exchange");
                context.setWriteSequenceNumber(0);
            }
        }
        adjustCompressionForDirection(false, context);
    }

    private static void adjustEncryptionForDirection(boolean receive, SshContext context) {
        Chooser chooser = context.getChooser();
        Optional<KeySet> keySet = context.getKeySet();
        if (keySet.isEmpty()) {
            LOGGER.warn(
                    "Unable to update the active {} cipher after handling a new keys message because key set is missing - workflow will continue with old cipher",
                    receive ? "decryption" : "encryption");
            return;
        }

        EncryptionAlgorithm encryptionAlgorithm;
        MacAlgorithm macAlgorithm;
        if (receive) {
            encryptionAlgorithm = chooser.getReceiveEncryptionAlgorithm();
            macAlgorithm = chooser.getReceiveMacAlgorithm();
            KeySet activeKeySet = context.getPacketLayer().getDecryptorCipher().getKeySet();
            EncryptionAlgorithm activeEncryptionAlgorithm =
                    context.getPacketLayer().getDecryptorCipher().getEncryptionAlgorithm();
            MacAlgorithm activeMacAlgorithm =
                    context.getPacketLayer().getDecryptorCipher().getMacAlgorithm();
            if (!context.getConfig().getForcePacketCipherChange()
                    && Objects.equals(activeKeySet, keySet.get())
                    && encryptionAlgorithm == activeEncryptionAlgorithm
                    && (encryptionAlgorithm.getType() == EncryptionAlgorithmType.AEAD
                            || macAlgorithm == activeMacAlgorithm)) {
                LOGGER.info(
                        "Key set and algorithms unchanged, not changing active decryption cipher - workflow will continue with old cipher");
                return;
            }
        } else {
            encryptionAlgorithm = chooser.getSendEncryptionAlgorithm();
            macAlgorithm = chooser.getSendMacAlgorithm();
            KeySet activeKeySet = context.getPacketLayer().getEncryptorCipher().getKeySet();
            EncryptionAlgorithm activeEncryptionAlgorithm =
                    context.getPacketLayer().getEncryptorCipher().getEncryptionAlgorithm();
            MacAlgorithm activeMacAlgorithm =
                    context.getPacketLayer().getEncryptorCipher().getMacAlgorithm();
            if (!context.getConfig().getForcePacketCipherChange()
                    && Objects.equals(activeKeySet, keySet.get())
                    && encryptionAlgorithm == activeEncryptionAlgorithm
                    && (encryptionAlgorithm.getType() == EncryptionAlgorithmType.AEAD
                            || macAlgorithm == activeMacAlgorithm)) {
                LOGGER.info(
                        "Key set and algorithms unchanged, not changing active decryption cipher - workflow will continue with old cipher");
                return;
            }
        }

        try {
            PacketCipher packetCipher =
                    PacketCipherFactory.getPacketCipher(
                            context,
                            keySet.get(),
                            encryptionAlgorithm,
                            macAlgorithm,
                            receive ? CipherMode.DECRYPT : CipherMode.ENCRYPT);
            if (receive) {
                context.getPacketLayer().updateDecryptionCipher(packetCipher);
            } else {
                context.getPacketLayer().updateEncryptionCipher(packetCipher);
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Caught an exception while trying to update the active {} cipher after handling a new keys message - workflow will continue with old cipher",
                    receive ? "decryption" : "encryption");
            LOGGER.debug(e);
        }
    }

    private static void adjustCompressionForDirection(boolean receive, SshContext context) {
        Chooser chooser = context.getChooser();
        CompressionMethod method =
                receive
                        ? chooser.getReceiveCompressionMethod()
                        : chooser.getSendCompressionMethod();
        if (method == CompressionMethod.ZLIB) {
            if (receive) {
                context.getPacketLayer().updateDecompressionAlgorithm(method.getAlgorithm());
            } else {
                context.getPacketLayer().updateCompressionAlgorithm(method.getAlgorithm());
            }
        }
    }

    @Override
    public NewKeysMessageParser getParser(byte[] array, SshContext context) {
        return new NewKeysMessageParser(array);
    }

    @Override
    public NewKeysMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new NewKeysMessageParser(array, startPosition);
    }

    public static final NewKeysMessagePreparator PREPARATOR = new NewKeysMessagePreparator();

    public static final NewKeysMessageSerializer SERIALIZER = new NewKeysMessageSerializer();
}
