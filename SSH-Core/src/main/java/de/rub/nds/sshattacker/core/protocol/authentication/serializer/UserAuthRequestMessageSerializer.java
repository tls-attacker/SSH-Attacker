/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UserAuthRequestMessageSerializer<T extends UserAuthRequestMessage<T>>
        extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthRequestMessageSerializer(T message) {
        super(message);
    }

    private void serializeUserName() {
        LOGGER.debug("User name length: " + message.getUserNameLength().getValue());
        appendInt(message.getUserNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("User name: " + message.getUserName().getValue());
        appendString(message.getUserName().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeServiceName() {
        LOGGER.debug("Service name length: " + message.getServiceNameLength().getValue());
        appendInt(
                message.getServiceNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Service name: " + message.getServiceName().getValue());
        appendString(message.getServiceName().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeMethodName() {
        LOGGER.debug("Method name length: " + message.getMethodNameLength().getValue());
        appendInt(message.getMethodNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Method name: " + message.getMethodName().getValue());
        appendString(message.getMethodName().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeUserName();
        serializeServiceName();
        serializeMethodName();
    }
}
