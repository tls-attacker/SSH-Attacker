/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.UnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.UnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageHandler extends SshMessageHandler<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageHandler(SshContext context) {
        super(context);
    }

    public UnknownMessageHandler(SshContext context, UnknownMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        LOGGER.debug(
                "Received unknown message:\n"
                        + ArrayConverter.bytesToHexString(message.getPayload()));
    }

    @Override
    public UnknownMessageParser getParser(byte[] array, int startPosition) {
        return new UnknownMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<UnknownMessage> getPreparator() {
        throw new NotImplementedException("UnknownMessageHandler::getPreparator");
    }

    @Override
    public UnknownMessageSerializer getSerializer() {
        return new UnknownMessageSerializer(message);
    }
}
