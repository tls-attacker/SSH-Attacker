/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewCompressMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewCompressMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewCompressMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewCompressMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NewCompressMessageHandler extends SshMessageHandler<NewCompressMessage>
        implements MessageSentHandler<NewCompressMessage> {

    @Override
    public void adjustContext(SshContext context, NewCompressMessage object) {
        // receiving NewCompressMessage when acting as server -> update compression algorithm
        if (!context.isHandleAsClient()
                && context.delayCompressionExtensionReceived()
                && context.getConfig().getRespectDelayCompressionExtension()) {
            context.getPacketLayer()
                    .updateDecompressionAlgorithm(
                            context.getSelectedDelayCompressionMethod()
                                    .orElse(CompressionMethod.NONE)
                                    .getAlgorithm());
        }
    }

    @Override
    public NewCompressMessageParser getParser(byte[] array, SshContext context) {
        return new NewCompressMessageParser(array);
    }

    @Override
    public NewCompressMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new NewCompressMessageParser(array, startPosition);
    }

    public static final NewCompressMessagePreparator PREPARATOR =
            new NewCompressMessagePreparator();

    public static final NewCompressMessageSerializer SERIALIZER =
            new NewCompressMessageSerializer();

    @Override
    public void adjustContextAfterMessageSent(SshContext context, NewCompressMessage object) {
        if (context.isClient()
                && context.delayCompressionExtensionReceived()
                && context.getConfig().getRespectDelayCompressionExtension()) {
            context.getPacketLayer()
                    .updateCompressionAlgorithm(
                            context.getSelectedDelayCompressionMethod()
                                    .orElse(CompressionMethod.NONE)
                                    .getAlgorithm());
        }
    }
}
