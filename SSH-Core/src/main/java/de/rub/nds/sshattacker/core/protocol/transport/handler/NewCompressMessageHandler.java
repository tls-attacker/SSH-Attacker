/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewCompressMessage;

public class NewCompressMessageHandler extends SshMessageHandler<NewCompressMessage>
        implements MessageSentHandler {

    public NewCompressMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(NewCompressMessage message) {
        // receiving NewCompressMessage when acting as server -> update compression algorithm
        if (!sshContext.isHandleAsClient()
                && sshContext.delayCompressionExtensionReceived()
                && sshContext.getConfig().getRespectDelayCompressionExtension()) {
            sshContext
                    .getPacketLayer()
                    .updateDecompressionAlgorithm(
                            sshContext
                                    .getSelectedDelayCompressionMethod()
                                    .orElse(CompressionMethod.NONE)
                                    .getAlgorithm());
        }
    }

    @Override
    public void adjustContextAfterMessageSent() {
        if (sshContext.isClient()
                && sshContext.delayCompressionExtensionReceived()
                && sshContext.getConfig().getRespectDelayCompressionExtension()) {
            sshContext
                    .getPacketLayer()
                    .updateCompressionAlgorithm(
                            sshContext
                                    .getSelectedDelayCompressionMethod()
                                    .orElse(CompressionMethod.NONE)
                                    .getAlgorithm());
        }
    }
}
