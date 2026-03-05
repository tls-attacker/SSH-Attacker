/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.UnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.UnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.UnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageHandler extends SshMessageHandler<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, UnknownMessage object) {
        LOGGER.debug(
                "Received unknown message:\n{}",
                () -> ArrayConverter.bytesToHexString(object.getPayload()));
    }

    @Override
    public UnknownMessageParser getParser(byte[] array, SshContext context) {
        return new UnknownMessageParser(array);
    }

    @Override
    public UnknownMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new UnknownMessageParser(array, startPosition);
    }

    public static final UnknownMessagePreparator PREPARATOR = new UnknownMessagePreparator();

    public static final UnknownMessageSerializer SERIALIZER = new UnknownMessageSerializer();
}
