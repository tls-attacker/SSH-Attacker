/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthFailureMessageSerializer extends MessageSerializer<UserAuthFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthFailureMessageSerializer(UserAuthFailureMessage msg) {
        super(msg);
    }

    private void serializePossibleAuthenticationMethods() {
        LOGGER.debug(
                "Possible authentication methods length: "
                        + msg.getPossibleAuthenticationMethodsLength().getValue());
        appendInt(
                msg.getPossibleAuthenticationMethodsLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Possible authentication methods: "
                        + msg.getPossibleAuthenticationMethods().getValue());
        appendString(msg.getPossibleAuthenticationMethods().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializePartialSuccess() {
        LOGGER.debug(
                "Partial success: " + Converter.byteToBoolean(msg.getPartialSuccess().getValue()));
        appendByte(msg.getPartialSuccess().getValue());
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializePossibleAuthenticationMethods();
        serializePartialSuccess();
    }
}
