/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugMessageHandler extends SshMessageHandler<DebugMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(DebugMessage message) {
        if (Converter.byteToBoolean(message.getAlwaysDisplay().getValue())) {
            LOGGER.info(
                    "DebugMessage retrieved from remote, message: {}",
                    message.getMessage().getValue());
        } else {
            LOGGER.debug(
                    "DebugMessage retrieved from remote, message: {}",
                    message.getMessage().getValue());
        }
    }
}
