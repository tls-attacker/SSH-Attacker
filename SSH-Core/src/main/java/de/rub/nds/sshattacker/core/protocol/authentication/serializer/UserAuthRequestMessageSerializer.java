/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UserAuthRequestMessageSerializer<T extends UserAuthRequestMessage<T>>
        extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected UserAuthRequestMessageSerializer(T message) {
        super(message);
    }

    private void serializeUserName() {
        Integer userNameLength = message.getUserNameLength().getValue();
        LOGGER.debug("User name length: {}", userNameLength);
        appendInt(userNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String userName = message.getUserName().getValue();
        LOGGER.debug("User name: {}", () -> backslashEscapeString(userName));
        appendString(userName, StandardCharsets.UTF_8);
    }

    private void serializeServiceName() {
        Integer serviceNameLength = message.getServiceNameLength().getValue();
        LOGGER.debug("Service name length: {}", serviceNameLength);
        appendInt(serviceNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String serviceName = message.getServiceName().getValue();
        LOGGER.debug("Service name: {}", () -> backslashEscapeString(serviceName));
        appendString(serviceName, StandardCharsets.US_ASCII);
    }

    private void serializeMethodName() {
        Integer methodNameLength = message.getMethodNameLength().getValue();
        LOGGER.debug("Method name length: {}", methodNameLength);
        appendInt(methodNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String methodName = message.getMethodName().getValue();
        LOGGER.debug("Method name: {}", () -> backslashEscapeString(methodName));
        appendString(methodName, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeUserName();
        serializeServiceName();
        serializeMethodName();
    }
}
