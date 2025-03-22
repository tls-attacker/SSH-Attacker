/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.NoFlowControlExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.NoFlowControlExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.NoFlowControlExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.NoFlowControlExtensionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NoFlowControlExtensionHandler
        extends AbstractExtensionHandler<NoFlowControlExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, NoFlowControlExtension object) {
        LOGGER.debug(
                "Remote peer signaled support for no-flow-control extension via SSH_MSG_EXT_INFO");
    }

    @Override
    public NoFlowControlExtensionParser getParser(byte[] array, SshContext context) {
        return new NoFlowControlExtensionParser(array);
    }

    @Override
    public NoFlowControlExtensionParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new NoFlowControlExtensionParser(array, startPosition);
    }

    public static final NoFlowControlExtensionPreparator PREPARATOR =
            new NoFlowControlExtensionPreparator();

    public static final NoFlowControlExtensionSerializer SERIALIZER =
            new NoFlowControlExtensionSerializer();
}
