/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEnvMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestEnvMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestEnvMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestEnvMessageSerializer(ChannelRequestEnvMessage message) {
        super(message);
    }

    public void serializeVariableName() {
        LOGGER.debug("Variable name length: " + message.getVariableNameLength().getValue());
        appendInt(
                message.getVariableNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Variable name: " + message.getVariableName().getValue());
        appendString(message.getVariableName().getValue(), StandardCharsets.UTF_8);
    }

    public void serializeVariableValue() {
        LOGGER.debug("Variable value length: " + message.getVariableValueLength().getValue());
        appendInt(
                message.getVariableValueLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Variable value: " + message.getVariableValue().getValue());
        appendString(message.getVariableValue().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeVariableName();
        serializeVariableValue();
    }
}
