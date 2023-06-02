/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UserAuthRequestMessageParser<T extends UserAuthRequestMessage<T>>
        extends SshMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*    public UserAuthRequestMessageParser(byte[] array) {
        super(array);
    }
    public UserAuthRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/

    public UserAuthRequestMessageParser(InputStream stream) {
        super(stream);
    }

    private void parseUserName(T message) {
        message.setUserNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Username length: " + message.getUserNameLength().getValue());
        message.setUserName(
                parseByteString(message.getUserNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Username: {}", backslashEscapeString(message.getUserName().getValue()));
    }

    private void parseServiceName(T message) {
        message.setServiceNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Servicename length: " + message.getServiceNameLength().getValue());
        message.setServiceName(
                parseByteString(
                        message.getServiceNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Servicename: {}", backslashEscapeString(message.getServiceName().getValue()));
    }

    private void parseMethodName(T message) {
        message.setMethodNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Methodname length: " + message.getMethodNameLength().getValue());
        message.setMethodName(
                parseByteString(
                        message.getMethodNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Methodname: {}", backslashEscapeString(message.getMethodName().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(T message) {
        parseUserName(message);
        parseServiceName(message);
        parseMethodName(message);
    }
}
