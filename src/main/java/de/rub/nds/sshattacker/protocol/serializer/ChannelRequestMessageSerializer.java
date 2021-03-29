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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestMessageSerializer extends MessageSerializer<ChannelRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ChannelRequestMessage msg;

    public ChannelRequestMessageSerializer(ChannelRequestMessage msg) {
        super(msg);
        this.msg = msg;
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("recipientChannel: " + msg.getRecipientChannel().getValue());
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
        LOGGER.debug("requestType: " + msg.getRequestType().getValue());
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getRequestType().getValue()));
        LOGGER.debug("replyWanted: " + msg.getReplyWanted().getValue());
        appendByte(msg.getReplyWanted().getValue());
        LOGGER.debug("payload: " + ArrayConverter.bytesToHexString(msg.getPayload().getValue()));
        appendBytes(msg.getPayload().getValue());
        return getAlreadySerialized();
    }

}
