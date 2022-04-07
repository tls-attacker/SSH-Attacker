/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelMessageParser<T extends ChannelMessage<T>>
        extends SshMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelMessageParser(byte[] array) {
        super(array);
    }

    public ChannelMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseRecipientChannel() {
        message.setRecipientChannel(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Recipient channel: " + message.getRecipientChannel().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseRecipientChannel();
    }
}
