/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySetGenerator;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewKeysMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;

public class NewKeysMessageHandler extends SshMessageHandler<NewKeysMessage>
        implements MessageSentHandler {

    public NewKeysMessageHandler(SshContext context) {
        super(context);
    }

    public NewKeysMessageHandler(SshContext context, NewKeysMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (context.getConfig().getEnableEncryptionOnNewKeysMessage()) {
            adjustEncryptionForDirection(true);
        }
        adjustCompressionForDirection(true);
    }

    @Override
    public void adjustContextAfterMessageSent() {
        if (context.getConfig().getEnableEncryptionOnNewKeysMessage()) {
            adjustEncryptionForDirection(false);
        }
        adjustCompressionForDirection(false);
    }

    private void adjustEncryptionForDirection(boolean receive) {
        Chooser chooser = context.getChooser();
        Optional<KeySet> keySet = context.getKeySet();
        EncryptionAlgorithm encryptionAlgorithm =
                receive
                        ? chooser.getReceiveEncryptionAlgorithm()
                        : chooser.getSendEncryptionAlgorithm();
        MacAlgorithm macAlgorithm =
                receive ? chooser.getReceiveMacAlgorithm() : chooser.getSendMacAlgorithm();
        if (keySet.isEmpty()) {
            LOGGER.warn(
                    "Unable to update the active {} cipher after handling a new keys message because key set is missing - workflow will continue with old cipher",
                    receive ? "decryption" : "encryption");
            return;
        }
        try {
            PacketCipher packetCipher =
                    PacketCipherFactory.getPacketCipher(
                            context, keySet.get(), encryptionAlgorithm, macAlgorithm);
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

    private void adjustCompressionForDirection(boolean receive) {
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
    }
}
