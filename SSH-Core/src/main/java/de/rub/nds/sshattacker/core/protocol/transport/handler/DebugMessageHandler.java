/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DebugMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DebugMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DebugMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugMessageHandler extends SshMessageHandler<DebugMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugMessageHandler(SshContext context) {
        super(context);
    }

    public DebugMessageHandler(SshContext context, DebugMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (Converter.byteToBoolean(message.getAlwaysDisplay().getValue())) {
            LOGGER.info(
                    "DebugMessage retrieved from remote, message: "
                            + message.getMessage().getValue());
        } else {
            LOGGER.debug(
                    "DebugMessage retrieved from remote, message: "
                            + message.getMessage().getValue());
        }
    }

    @Override
    public DebugMessageParser getParser(byte[] array, int startPosition) {
        return new DebugMessageParser(array, startPosition);
    }

    @Override
    public DebugMessagePreparator getPreparator() {
        return new DebugMessagePreparator(context, message);
    }

    @Override
    public DebugMessageSerializer getSerializer() {
        return new DebugMessageSerializer(message);
    }
}
