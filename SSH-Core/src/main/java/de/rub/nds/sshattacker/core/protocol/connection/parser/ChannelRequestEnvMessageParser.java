/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEnvMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestEnvMessageParser
        extends ChannelRequestMessageParser<ChannelRequestEnvMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestEnvMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestEnvMessage createMessage() {
        return new ChannelRequestEnvMessage();
    }

    public void parseVariableName() {
        message.setVariableNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Variable name length: " + message.getVariableNameLength().getValue());
        message.setVariableName(parseByteString(message.getVariableNameLength().getValue()));
        LOGGER.debug("Variable name: " + message.getVariableName().getValue());
    }

    public void parseVariableValue() {
        message.setVariableValueLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Variable value length: " + message.getVariableValueLength().getValue());
        message.setVariableValue(parseByteString(message.getVariableValueLength().getValue()));
        LOGGER.debug("Variable value: " + message.getVariableValue().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseVariableName();
        parseVariableValue();
    }
}
