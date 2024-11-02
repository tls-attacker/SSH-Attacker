/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.response;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseStatusMessage;
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
        Integer statusCode = message.getStatusCode().getValue();
        LOGGER.debug("StatusCode: {}", statusCode);
        appendInt(statusCode, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeErrorMessage() {
        Integer errorMessageLength = message.getErrorMessageLength().getValue();
        LOGGER.debug("ErrorMessage length: {}", errorMessageLength);
        appendInt(errorMessageLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String errorMessage = message.getErrorMessage().getValue();
        LOGGER.debug("ErrorMessage: {}", () -> backslashEscapeString(errorMessage));
        appendString(errorMessage, StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        Integer languageTagLength = message.getLanguageTagLength().getValue();
        LOGGER.debug("LanguageTag length: {}", languageTagLength);
        appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = message.getLanguageTag().getValue();
        LOGGER.debug("LanguageTag: {}", () -> backslashEscapeString(languageTag));
        appendString(languageTag, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeResponseSpecificContents() {
        serializeStatusCode();
        serializeErrorMessage();
        serializeLanguageTag();
    }
}
