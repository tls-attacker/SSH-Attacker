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
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UserAuthRequestMessageSerializer<T extends UserAuthRequestMessage<T>>
        extends MessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthRequestMessageSerializer(T msg) {
        super(msg);
    }

    private void serializeUserName() {
        LOGGER.debug("User name length: " + msg.getUserNameLength().getValue());
        appendInt(msg.getUserNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("User name: " + msg.getUserName().getValue());
        appendString(msg.getUserName().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeServiceName() {
        LOGGER.debug("Service name length: " + msg.getServiceNameLength().getValue());
        appendInt(msg.getServiceNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Service name: " + msg.getServiceName().getValue());
        appendString(msg.getServiceName().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeMethodName() {
        LOGGER.debug("Method name length: " + msg.getMethodNameLength().getValue());
        appendInt(msg.getMethodNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Method name: " + msg.getMethodName().getValue());
        appendString(msg.getMethodName().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializeUserName();
        serializeServiceName();
        serializeMethodName();
    }
}
