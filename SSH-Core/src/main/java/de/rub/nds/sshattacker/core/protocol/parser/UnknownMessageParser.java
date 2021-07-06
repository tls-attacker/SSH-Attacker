/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.sshattacker.core.protocol.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;

public class UnknownMessageParser extends MessageParser<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UnknownMessage createMessage() {
        return new UnknownMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(UnknownMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
        LOGGER.debug("Payload: " + Arrays.toString(msg.getPayload().getValue()));
    }
}
