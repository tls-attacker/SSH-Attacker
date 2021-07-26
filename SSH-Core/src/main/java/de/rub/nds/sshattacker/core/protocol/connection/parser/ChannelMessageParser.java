/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelMessageParser<T extends ChannelMessage<T>> extends MessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseRecipientChannel(T msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Recipient channel: " + msg.getRecipientChannel().getValue());
    }

    @Override
    protected void parseMessageSpecificPayload(T msg) {
        parseRecipientChannel(msg);
    }
}
