/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewCompressMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewCompressMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewCompressMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewCompressMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NewCompressMessageHandler extends SshMessageHandler<NewCompressMessage> {

    public NewCompressMessageHandler(SshContext context) {
        super(context);
    }

    public NewCompressMessageHandler(SshContext context, NewCompressMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // receiving NewCompressMessage when acting as server -> update compression algorithm
        if (!context.isHandleAsClient()
                && context.delayCompressionExtensionReceived()
                && context.getConfig().getEnableExtensions()) {
            context.getPacketLayer()
                    .updateCompressionAlgorithm(
                            context.getSelectedDelayCompressionMethod().get().getAlgorithm());
            context.getPacketLayer()
                    .updateDecompressionAlgorithm(
                            context.getSelectedDelayCompressionMethod().get().getAlgorithm());
        }
    }

    @Override
    public NewCompressMessageParser getParser(byte[] array) {
        return new NewCompressMessageParser(array);
    }

    @Override
    public NewCompressMessageParser getParser(byte[] array, int startPosition) {
        return new NewCompressMessageParser(array, startPosition);
    }

    @Override
    public NewCompressMessagePreparator getPreparator() {
        return new NewCompressMessagePreparator(context.getChooser(), message);
    }

    @Override
    public NewCompressMessageSerializer getSerializer() {
        return new NewCompressMessageSerializer(message);
    }
}
