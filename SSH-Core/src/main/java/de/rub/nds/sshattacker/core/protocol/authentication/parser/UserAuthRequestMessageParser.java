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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UserAuthRequestMessageParser<T extends UserAuthRequestMessage<T>>
        extends SshMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected UserAuthRequestMessageParser(byte[] array) {
        super(array);
    }

    protected UserAuthRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseUserName() {
        int userNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setUserNameLength(userNameLength);
        LOGGER.debug("Username length: {}", userNameLength);
        String userName = parseByteString(userNameLength, StandardCharsets.US_ASCII);
        message.setUserName(userName);
        LOGGER.debug("Username: {}", () -> backslashEscapeString(userName));
    }

    private void parseServiceName() {
        int serviceNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setServiceNameLength(serviceNameLength);
        LOGGER.debug("Servicename length: {}", serviceNameLength);
        String serviceName = parseByteString(serviceNameLength, StandardCharsets.US_ASCII);
        message.setServiceName(serviceName);
        LOGGER.debug("Servicename: {}", () -> backslashEscapeString(serviceName));
    }

    private void parseMethodName() {
        int methodNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setMethodNameLength(methodNameLength);
        LOGGER.debug("Methodname length: {}", methodNameLength);
        String methodName = parseByteString(methodNameLength, StandardCharsets.US_ASCII);
        message.setMethodName(methodName);
        LOGGER.debug("Methodname: {}", () -> backslashEscapeString(methodName));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseUserName();
        parseServiceName();
        parseMethodName();
    }
}
