/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
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

    @Override
    public void adjustContext(SshContext context, DebugMessage object) {
        if (Converter.byteToBoolean(object.getAlwaysDisplay().getValue())) {
            LOGGER.info(
                    "DebugMessage retrieved from remote, message: {}",
                    object.getMessage().getValue());
        } else {
            LOGGER.debug(
                    "DebugMessage retrieved from remote, message: {}",
                    object.getMessage().getValue());
        }
    }

    @Override
    public DebugMessageParser getParser(byte[] array, SshContext context) {
        return new DebugMessageParser(array);
    }

    @Override
    public DebugMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new DebugMessageParser(array, startPosition);
    }

    public static final DebugMessagePreparator PREPARATOR = new DebugMessagePreparator();

    public static final DebugMessageSerializer SERIALIZER = new DebugMessageSerializer();
}
