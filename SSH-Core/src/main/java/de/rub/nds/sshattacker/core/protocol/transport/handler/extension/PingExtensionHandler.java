/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PingExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.PingExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.PingExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.PingExtensionSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingExtensionHandler extends AbstractExtensionHandler<PingExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PingExtensionHandler(SshContext context) {
        super(context);
    }

    public PingExtensionHandler(SshContext context, PingExtension extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        LOGGER.info(
                "Remote peer signaled support for ping@openssh.com extension via SSH_MSG_EXT_INFO");
    }

    @Override
    public PingExtensionParser getParser(byte[] array) {
        return new PingExtensionParser(array);
    }

    @Override
    public PingExtensionParser getParser(byte[] array, int startPosition) {
        return new PingExtensionParser(array, startPosition);
    }

    @Override
    public PingExtensionPreparator getPreparator() {
        return new PingExtensionPreparator(context.getChooser(), extension);
    }

    @Override
    public PingExtensionSerializer getSerializer() {
        return new PingExtensionSerializer(extension);
    }
}
