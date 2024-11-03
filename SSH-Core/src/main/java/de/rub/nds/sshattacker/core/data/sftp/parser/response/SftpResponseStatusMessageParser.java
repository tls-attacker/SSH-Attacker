/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.response;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpStatusCode;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseStatusMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseStatusMessageParser
        extends SftpResponseMessageParser<SftpResponseStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseStatusMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseStatusMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseStatusMessage createMessage() {
        return new SftpResponseStatusMessage();
    }

    private void parseStatusCode() {
        int statusCode = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setStatusCode(statusCode);
        LOGGER.debug("StatusCode: {}", SftpStatusCode.getNameByCode(statusCode));
    }

    private void parseErrorMessage() {
        int errorMessageLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setErrorMessageLength(errorMessageLength);
        LOGGER.debug("ErrorMessage length: {}", errorMessageLength);
        String errorMessage = parseByteString(errorMessageLength, StandardCharsets.UTF_8);
        message.setErrorMessage(errorMessage);
        LOGGER.debug("ErrorMessage: {}", () -> backslashEscapeString(errorMessage));
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("LanguageTag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength, StandardCharsets.US_ASCII);
        message.setLanguageTag(languageTag);
        LOGGER.debug("LanguageTag: {}", () -> backslashEscapeString(languageTag));
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseStatusCode();
        parseErrorMessage();
        parseLanguageTag();
    }
}
