/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenMessageSerializer extends MessageSerializer<ChannelOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenMessageSerializer(ChannelOpenMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("channel type: " + msg.getChannelType().getValue());
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getChannelType().getValue()));
        LOGGER.debug("senderChannel: " + msg.getSenderChannel().getValue());
        appendInt(msg.getSenderChannel().getValue(), DataFormatConstants.INT32_SIZE);
        LOGGER.debug("windowSize: " + msg.getWindowSize().getValue());
        appendInt(msg.getWindowSize().getValue(), DataFormatConstants.INT32_SIZE);
        LOGGER.debug("packetSize: " + msg.getPacketSize().getValue());
        appendInt(msg.getPacketSize().getValue(), DataFormatConstants.INT32_SIZE);
        return getAlreadySerialized();
    }

}
