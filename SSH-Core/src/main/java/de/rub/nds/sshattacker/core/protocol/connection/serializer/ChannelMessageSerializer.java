/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelMessageSerializer<T extends ChannelMessage<T>> extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelMessageSerializer(T message) {
        super(message);
    }

    private void serializeRecipientChannel() {
        LOGGER.debug("Recipient channel: " + message.getRecipientChannel().getValue());
        appendInt(message.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeRecipientChannel();
    }
}
