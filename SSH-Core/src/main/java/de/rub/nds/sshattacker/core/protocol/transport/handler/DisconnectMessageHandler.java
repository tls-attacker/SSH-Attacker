/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DisconnectMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DisconnectMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DisconnectMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageHandler extends SshMessageHandler<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageHandler(SshContext context) {
        super(context);
    }

    public DisconnectMessageHandler(SshContext context, DisconnectMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        LOGGER.info("Received DisconnectMessage");
        context.setReceivedDisconnectMessage(true);
    }

    @Override
    public DisconnectMessageParser getParser(byte[] array, int startPosition) {
        return new DisconnectMessageParser(array, startPosition);
    }

    @Override
    public DisconnectMessagePreparator getPreparator() {
        return new DisconnectMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DisconnectMessageSerializer getSerializer() {
        return new DisconnectMessageSerializer(message);
    }
}
