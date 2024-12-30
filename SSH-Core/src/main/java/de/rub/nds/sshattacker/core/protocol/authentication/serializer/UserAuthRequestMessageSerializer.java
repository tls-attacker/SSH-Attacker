/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UserAuthRequestMessageSerializer<T extends UserAuthRequestMessage<T>>
        extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeUserName(T object, SerializerStream output) {
        Integer userNameLength = object.getUserNameLength().getValue();
        LOGGER.debug("User name length: {}", userNameLength);
        output.appendInt(userNameLength);
        String userName = object.getUserName().getValue();
        LOGGER.debug("User name: {}", () -> backslashEscapeString(userName));
        output.appendString(userName, StandardCharsets.UTF_8);
    }

    private void serializeServiceName(T object, SerializerStream output) {
        Integer serviceNameLength = object.getServiceNameLength().getValue();
        LOGGER.debug("Service name length: {}", serviceNameLength);
        output.appendInt(serviceNameLength);
        String serviceName = object.getServiceName().getValue();
        LOGGER.debug("Service name: {}", () -> backslashEscapeString(serviceName));
        output.appendString(serviceName, StandardCharsets.US_ASCII);
    }

    private void serializeMethodName(T object, SerializerStream output) {
        Integer methodNameLength = object.getMethodNameLength().getValue();
        LOGGER.debug("Method name length: {}", methodNameLength);
        output.appendInt(methodNameLength);
        String methodName = object.getMethodName().getValue();
        LOGGER.debug("Method name: {}", () -> backslashEscapeString(methodName));
        output.appendString(methodName, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents(T object, SerializerStream output) {
        serializeUserName(object, output);
        serializeServiceName(object, output);
        serializeMethodName(object, output);
    }
}
