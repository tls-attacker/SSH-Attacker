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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ChannelOpenFailureMessageSerializer extends ChannelMessageSerializer<ChannelOpenFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenFailureMessageSerializer(ChannelOpenFailureMessage msg) {
        super(msg);
    }

    private void serializeReasonCode() {
        LOGGER.debug("Reason code: " + msg.getReasonCode().getValue());
        appendInt(msg.getReasonCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeReason() {
        LOGGER.debug("Reason length: " + msg.getReasonLength().getValue());
        appendInt(msg.getReasonLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Reason: " + msg.getReason().getValue());
        appendString(msg.getReason().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: " + msg.getLanguageTagLength().getValue());
        appendInt(msg.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Language tag: " + msg.getLanguageTag().getValue());
        appendString(msg.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        super.serializeMessageSpecificPayload();
        serializeReasonCode();
        serializeReason();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
