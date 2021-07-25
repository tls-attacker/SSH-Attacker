/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageParser extends MessageParser<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public DisconnectMessage createMessage() {
        return new DisconnectMessage();
    }

    private void parseReasonCode(DisconnectMessage msg) {
        msg.setReasonCode(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("ReasonCode: " + msg.getReasonCode().getValue());
    }

    private void parseDescription(DisconnectMessage msg) {
        int length = parseIntField(DataFormatConstants.INT32_SIZE);
        LOGGER.debug("DescriptionLength: " + length);
        msg.setDescription(parseByteString(length));
        LOGGER.debug("Description: " + msg.getDescription().getValue());
    }

    private void parseLanguageTag(DisconnectMessage msg) {
        int length = parseIntField(DataFormatConstants.INT32_SIZE);
        LOGGER.debug("LanguageTagLength: " + length);
        msg.setLanguageTag(parseByteString(length));
        LOGGER.debug("LanguageTag" + msg.getLanguageTag().getValue());

    }

    @Override
    protected void parseMessageSpecificPayload(DisconnectMessage msg) {
        parseReasonCode(msg);
        parseDescription(msg);
        parseLanguageTag(msg);

    }

}
