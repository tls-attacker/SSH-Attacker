/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.PongMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.PongMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.PongMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.PongMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PongMessageHandler extends SshMessageHandler<PongMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PongMessageHandler(SshContext context) {
        super(context);
    }

    public PongMessageHandler(SshContext context, PongMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        LOGGER.debug(
                "PongMessage received from remote, responded data length: {}",
                message.getDataLength().getValue());
    }

    @Override
    public PongMessageParser getParser(byte[] array) {
        return new PongMessageParser(array);
    }

    @Override
    public PongMessageParser getParser(byte[] array, int startPosition) {
        return new PongMessageParser(array, startPosition);
    }

    public static final PongMessagePreparator PREPARATOR = new PongMessagePreparator();

    @Override
    public PongMessageSerializer getSerializer() {
        return new PongMessageSerializer(message);
    }
}
