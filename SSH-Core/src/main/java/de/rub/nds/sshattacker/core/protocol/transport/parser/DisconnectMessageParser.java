/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageParser extends SshMessageParser<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageParser(InputStream stream) {
        super(stream);
    }

    private void parseReasonCode(DisconnectMessage message) {
        message.setReasonCode(parseIntField(DataFormatConstants.UINT32_SIZE));
        if (DisconnectReason.fromId(message.getReasonCode().getValue()) != null) {
            LOGGER.debug(
                    "Reason: {} (Code: {})",
                    DisconnectReason.fromId(message.getReasonCode().getValue()).toString(),
                    message.getReasonCode().getValue());
        } else {
            LOGGER.debug("Reason: [unknown] (Code: {})", message.getReasonCode().getValue());
        }
    }

    private void parseDescription(DisconnectMessage message) {
        message.setDescriptionLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Description length: {}", message.getDescriptionLength().getValue());
        message.setDescription(
                parseByteString(message.getDescriptionLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Description: {}", backslashEscapeString(message.getDescription().getValue()));
    }

    private void parseLanguageTag(DisconnectMessage message) {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: {}", message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Language tag: {}", backslashEscapeString(message.getLanguageTag().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(DisconnectMessage message) {
        parseReasonCode(message);
        parseDescription(message);
        parseLanguageTag(message);
    }

    @Override
    public void parse(DisconnectMessage message) {
        parseProtocolMessageContents(message);
    }
}
