/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySetGenerator;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewKeysMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NewKeysMessageHandler extends SshMessageHandler<NewKeysMessage> {

    public NewKeysMessageHandler(SshContext context) {
        super(context);
    }

    public NewKeysMessageHandler(SshContext context, NewKeysMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        try {
            if (context.getConfig().getEnableEncryptionOnNewKeysMessage()) {
                KeySet keySet = KeySetGenerator.generateKeySet(context);
                EncryptionAlgorithm inEnc =
                        context.isClient()
                                ? context.getCipherAlgorithmServerToClient()
                                        .orElseThrow(WorkflowExecutionException::new)
                                : context.getCipherAlgorithmClientToServer()
                                        .orElseThrow(WorkflowExecutionException::new);
                MacAlgorithm inMac =
                        context.isClient()
                                ? context.getMacAlgorithmServerToClient()
                                        .orElseThrow(WorkflowExecutionException::new)
                                : context.getMacAlgorithmClientToServer()
                                        .orElseThrow(WorkflowExecutionException::new);
                context.getPacketLayer()
                        .updateDecryptionCipher(
                                PacketCipherFactory.getPacketCipher(context, keySet, inEnc, inMac));
            }
        } catch (IllegalArgumentException e) {
            raiseAdjustmentException(new AdjustmentException(e));
        }

        // Enable decompression of further messages if negotiated
        CompressionMethod decompressionMethod =
                (context.isClient()
                                ? context.getCompressionMethodServerToClient()
                                : context.getCompressionMethodClientToServer())
                        .orElse(CompressionMethod.NONE);
        if (decompressionMethod == CompressionMethod.ZLIB) {
            context.getPacketLayer()
                    .updateDecompressionAlgorithm(decompressionMethod.getAlgorithm());
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
