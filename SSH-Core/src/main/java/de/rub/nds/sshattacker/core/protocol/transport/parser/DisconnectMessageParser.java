/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageParser extends SshMessageParser<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DisconnectMessage createMessage() {
        return new DisconnectMessage();
    }

    private void parseReasonCode() {
        message.setReasonCode(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug(
                "Reason: "
                        + DisconnectReason.fromId(message.getReasonCode().getValue()).toString()
                        + " (Code: "
                        + message.getReasonCode().getValue()
                        + ")");
    }

    private void parseDescription() {
        message.setDescriptionLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Description length: " + message.getDescriptionLength().getValue());
        message.setDescription(
                parseByteString(message.getDescriptionLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Description: " + message.getDescription().getValue());
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: " + message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Language tag: " + message.getLanguageTag().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseReasonCode();
        parseDescription();
        parseLanguageTag();
    }
}
