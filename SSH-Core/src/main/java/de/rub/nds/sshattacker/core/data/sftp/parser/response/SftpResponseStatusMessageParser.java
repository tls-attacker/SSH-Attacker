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
        message.setStatusCode(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("StatusCode: {}", message.getStatusCode().getValue());
    }

    private void parseErrorMessage() {
        message.setErrorMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("ErrorMessage length: {}", message.getErrorMessageLength().getValue());
        message.setErrorMessage(
                parseByteString(
                        message.getErrorMessageLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "ErrorMessage: {}",
                () -> backslashEscapeString(message.getErrorMessage().getValue()));
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("LanguageTag length: {}", message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug(
                "LanguageTag: {}",
                () -> backslashEscapeString(message.getLanguageTag().getValue()));
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseStatusCode();
        parseErrorMessage();
        parseLanguageTag();
    }
}
