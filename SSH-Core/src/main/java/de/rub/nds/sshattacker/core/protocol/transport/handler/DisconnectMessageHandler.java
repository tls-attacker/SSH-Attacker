/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DisconnectMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DisconnectMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DisconnectMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageHandler extends SshMessageHandler<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, DisconnectMessage object) {
        LOGGER.warn("Received DisconnectMessage");
        context.setDisconnectMessageReceived(true);
    }

    @Override
    public DisconnectMessageParser getParser(byte[] array, SshContext context) {
        return new DisconnectMessageParser(array);
    }

    @Override
    public DisconnectMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new DisconnectMessageParser(array, startPosition);
    }

    public static final DisconnectMessagePreparator PREPARATOR = new DisconnectMessagePreparator();

    public static final DisconnectMessageSerializer SERIALIZER = new DisconnectMessageSerializer();
}
