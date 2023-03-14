/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDefaultMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenDefaultMessageParser
        extends ChannelOpenMessageParser<ChannelOpenDefaultMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenDefaultMessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenDefaultMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelOpenDefaultMessage createMessage() {
        return new ChannelOpenDefaultMessage();
    }
}
