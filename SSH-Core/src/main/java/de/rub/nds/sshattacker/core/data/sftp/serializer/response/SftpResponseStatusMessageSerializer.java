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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseStatusMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeStatusCode(
            SftpResponseStatusMessage object, SerializerStream output) {
        Integer statusCode = object.getStatusCode().getValue();
        LOGGER.debug("StatusCode: {}", statusCode);
        output.appendInt(statusCode, DataFormatConstants.UINT32_SIZE);
    }

    private static void serializeErrorMessage(
            SftpResponseStatusMessage object, SerializerStream output) {
        Integer errorMessageLength = object.getErrorMessageLength().getValue();
        LOGGER.debug("ErrorMessage length: {}", errorMessageLength);
        output.appendInt(errorMessageLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String errorMessage = object.getErrorMessage().getValue();
        LOGGER.debug("ErrorMessage: {}", () -> backslashEscapeString(errorMessage));
        output.appendString(errorMessage, StandardCharsets.UTF_8);
    }

    private static void serializeLanguageTag(
            SftpResponseStatusMessage object, SerializerStream output) {
        Integer languageTagLength = object.getLanguageTagLength().getValue();
        LOGGER.debug("LanguageTag length: {}", languageTagLength);
        output.appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = object.getLanguageTag().getValue();
        LOGGER.debug("LanguageTag: {}", () -> backslashEscapeString(languageTag));
        output.appendString(languageTag, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseStatusMessage object, SerializerStream output) {
        serializeStatusCode(object, output);
        serializeErrorMessage(object, output);
        serializeLanguageTag(object, output);
    }
}
