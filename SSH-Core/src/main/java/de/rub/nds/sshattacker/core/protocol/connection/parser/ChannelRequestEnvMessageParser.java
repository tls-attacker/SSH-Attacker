/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEnvMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestEnvMessageParser
        extends ChannelRequestMessageParser<ChannelRequestEnvMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestEnvMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestEnvMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestEnvMessage createMessage() {
        return new ChannelRequestEnvMessage();
    }

    private void parseVariableName() {
        int variableNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setVariableNameLength(variableNameLength);
        LOGGER.debug("Variable name length: {}", variableNameLength);
        String variableName = parseByteString(variableNameLength);
        message.setVariableName(variableName);
        LOGGER.debug("Variable name: {}", () -> backslashEscapeString(variableName));
    }

    private void parseVariableValue() {
        int variableValueLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setVariableValueLength(variableValueLength);
        LOGGER.debug("Variable value length: {}", variableValueLength);
        String variableValue = parseByteString(variableValueLength);
        message.setVariableValue(variableValue);
        LOGGER.debug("Variable value: {}", () -> backslashEscapeString(variableValue));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseVariableName();
        parseVariableValue();
    }
}
