/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelDataMessage;
import de.rub.nds.sshattacker.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageSerializer extends MessageSerializer<ChannelDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageSerializer(ChannelDataMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("recipientChannel: " + msg.getRecipientChannel().getValue());
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
        LOGGER.debug("data: " + new String(msg.getData().getValue()));
        appendBytes(Converter.bytesToLengthPrefixedBinaryString(msg.getData().getValue()));
        return getAlreadySerialized();
    }

}
