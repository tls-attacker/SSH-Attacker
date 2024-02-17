/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.cipher.keys.AbstractKeySet;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Objects;
import java.util.Optional;

public class NewKeysMessageHandler extends SshMessageHandler<NewKeysMessage>
        implements MessageSentHandler {

    public NewKeysMessageHandler(SshContext context) {
        super(context);
    }

    /*public NewKeysMessageHandler(SshContext context, NewKeysMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(NewKeysMessage message) {
        if (sshContext.getConfig().getEnableEncryptionOnNewKeysMessage()) {
            adjustEncryptionForDirection(true);
            if (context.getStrictKeyExchangeEnabled().orElse(false)) {
                LOGGER.info("Resetting read sequence number to 0 because of strict key exchange");
                context.setReadSequenceNumber(0);
            }
        }
        adjustCompressionForDirection(true);
    }

    @Override
    public void adjustContextAfterMessageSent() {
        if (sshContext.getConfig().getEnableEncryptionOnNewKeysMessage()) {
            adjustEncryptionForDirection(false);
            if (context.getStrictKeyExchangeEnabled().orElse(false)) {
                LOGGER.info("Resetting write sequence number to 0 because of strict key exchange");
                context.setWriteSequenceNumber(0);
            }
        }
        adjustCompressionForDirection(false);
    }

    private void adjustEncryptionForDirection(boolean receive) {
        Chooser chooser = sshContext.getChooser();
        Optional<AbstractKeySet> keySet = sshContext.getKeySet();
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
            AbstractKeySet activeKeySet =
                    sshContext.getPacketLayer().getDecryptorCipher().getKeySet();
            EncryptionAlgorithm activeEncryptionAlgorithm =
                    sshContext.getPacketLayer().getDecryptorCipher().getEncryptionAlgorithm();
            MacAlgorithm activeMacAlgorithm =
                    sshContext.getPacketLayer().getDecryptorCipher().getMacAlgorithm();
            if (!sshContext.getConfig().getForcePacketCipherChange()
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
            AbstractKeySet activeKeySet =
                    sshContext.getPacketLayer().getEncryptorCipher().getKeySet();
            EncryptionAlgorithm activeEncryptionAlgorithm =
                    sshContext.getPacketLayer().getEncryptorCipher().getEncryptionAlgorithm();
            MacAlgorithm activeMacAlgorithm =
                    sshContext.getPacketLayer().getEncryptorCipher().getMacAlgorithm();
            if (!sshContext.getConfig().getForcePacketCipherChange()
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
                            sshContext,
                            keySet.get(),
                            encryptionAlgorithm,
                            macAlgorithm,
                            receive ? CipherMode.DECRYPT : CipherMode.ENCRYPT);
            if (receive) {
                sshContext.getPacketLayer().updateDecryptionCipher(packetCipher);
            } else {
                sshContext.getPacketLayer().updateEncryptionCipher(packetCipher);
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Caught an exception while trying to update the active {} cipher after handling a new keys message - workflow will continue with old cipher",
                    receive ? "decryption" : "encryption");
            LOGGER.debug(e);
        }
    }

    private void adjustCompressionForDirection(boolean receive) {
        Chooser chooser = sshContext.getChooser();
        CompressionMethod method =
                receive
                        ? chooser.getReceiveCompressionMethod()
                        : chooser.getSendCompressionMethod();
        if (method == CompressionMethod.ZLIB) {
            if (receive) {
                sshContext.getPacketLayer().updateDecompressionAlgorithm(method.getAlgorithm());
            } else {
                sshContext.getPacketLayer().updateCompressionAlgorithm(method.getAlgorithm());
            }
        }
    }

    /*@Override
    public NewKeysMessageParser getParser(byte[] array) {
        return new NewKeysMessageParser(array);
    }

    @Override
    public NewKeysMessageParser getParser(byte[] array, int startPosition) {
        return new NewKeysMessageParser(array, startPosition);
    }

    @Override
    public NewKeysMessagePreparator getPreparator() {
        return new NewKeysMessagePreparator(context.getChooser(), message);
    }

    @Override
    public NewKeysMessageSerializer getSerializer() {
        return new NewKeysMessageSerializer(message);
    }*/
}
