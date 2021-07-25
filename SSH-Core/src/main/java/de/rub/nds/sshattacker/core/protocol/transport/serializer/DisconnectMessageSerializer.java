/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageSerializer extends MessageSerializer<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageSerializer(DisconnectMessage msg) {
        super(msg);
    }

    private void serializeReasonCode() {
        LOGGER.debug("ReasonCode: " + msg.getReasonCode().getValue());
        appendInt(msg.getReasonCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeDescription() {
        int length = msg.getDescription().getValue().length();
        LOGGER.debug("DescriptionLength: " + length);
        appendInt(length, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: " + msg.getDescription().getValue());
        appendString(msg.getDescription().getValue());
    }

    private void serializeLanguageTag() {
        int length = msg.getLanguageTag().getValue().length();
        appendInt(length, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("LanguageTag: " + msg.getLanguageTag().getValue());
        appendString(msg.getLanguageTag().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeReasonCode();
        serializeDescription();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
