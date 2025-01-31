/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.PingMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.PingMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.PingMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.PingMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingMessageHandler extends SshMessageHandler<PingMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, PingMessage object) {
        LOGGER.debug(
                "PingMessage received from remote, data to respond length: {}",
                () -> object.getDataLength().getValue());
    }

    @Override
    public PingMessageParser getParser(byte[] array, SshContext context) {
        return new PingMessageParser(array);
    }

    @Override
    public PingMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new PingMessageParser(array, startPosition);
    }

    public static final PingMessagePreparator PREPARATOR = new PingMessagePreparator();

    public static final PingMessageSerializer SERIALIZER = new PingMessageSerializer();
}
