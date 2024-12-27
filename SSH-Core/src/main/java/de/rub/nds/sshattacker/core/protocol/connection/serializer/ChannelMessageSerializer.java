/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelMessageSerializer<T extends ChannelMessage<T>> extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeRecipientChannel(T object, SerializerStream output) {
        Integer recipientChannelId = object.getRecipientChannelId().getValue();
        LOGGER.debug("Recipient channel id: {}", recipientChannelId);
        output.appendInt(recipientChannelId, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents(T object, SerializerStream output) {
        serializeRecipientChannel(object, output);
    }
}
