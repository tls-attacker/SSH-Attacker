/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;

public class UnknownMessageParser extends MessageParser<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public UnknownMessage createMessage() {
        return new UnknownMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(UnknownMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
        LOGGER.debug("Payload: " + ArrayConverter.bytesToRawHexString(msg.getPayload().getValue()));
    }
}
