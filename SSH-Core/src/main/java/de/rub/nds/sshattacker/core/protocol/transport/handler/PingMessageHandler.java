/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.PingMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingMessageHandler extends SshMessageHandler<PingMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PingMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(PingMessage message) {
        LOGGER.debug(
                "PingMessage received from remote, data to respond length: {}",
                message.getDataLength().getValue());
    }
}
