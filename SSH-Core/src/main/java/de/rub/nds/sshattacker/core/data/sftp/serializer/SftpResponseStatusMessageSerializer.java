/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseStatusMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseStatusMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseStatusMessageSerializer(SftpResponseStatusMessage message) {
        super(message);
    }

    private void serializeStatusCode() {
        LOGGER.debug("StatusCode: {}", message.getStatusCode().getValue());
        appendInt(message.getStatusCode().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeErrorMessage() {
        LOGGER.debug("ErrorMessage length: {}", message.getErrorMessageLength().getValue());
        appendInt(
                message.getErrorMessageLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "ErrorMessage: {}",
                () -> backslashEscapeString(message.getErrorMessage().getValue()));
        appendString(message.getErrorMessage().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        LOGGER.debug("LanguageTag length: {}", message.getLanguageTagLength().getValue());
        appendInt(
                message.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "LanguageTag: {}",
                () -> backslashEscapeString(message.getLanguageTag().getValue()));
        appendString(message.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeResponseSpecificContents() {
        serializeStatusCode();
        serializeErrorMessage();
        serializeLanguageTag();
    }
}
