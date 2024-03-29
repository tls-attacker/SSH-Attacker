/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageHandler extends SshMessageHandler<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(UnknownMessage message) {
        LOGGER.debug(
                "Received unknown message:\n{}",
                ArrayConverter.bytesToHexString(message.getPayload()));
    }
}
