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
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestEnvMessageParser
        extends ChannelRequestMessageParser<ChannelRequestEnvMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestEnvMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelRequestEnvMessage message) {
        parseProtocolMessageContents(message);
    }

    public void parseVariableName(ChannelRequestEnvMessage message) {
        message.setVariableNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Variable name length: {}", message.getVariableNameLength().getValue());
        message.setVariableName(parseByteString(message.getVariableNameLength().getValue()));
        LOGGER.debug(
                "Variable name: {}", backslashEscapeString(message.getVariableName().getValue()));
    }

    public void parseVariableValue(ChannelRequestEnvMessage message) {
        message.setVariableValueLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Variable value length: {}", message.getVariableValueLength().getValue());
        message.setVariableValue(parseByteString(message.getVariableValueLength().getValue()));
        LOGGER.debug(
                "Variable value: {}", backslashEscapeString(message.getVariableValue().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(ChannelRequestEnvMessage message) {
        super.parseMessageSpecificContents(message);
        parseVariableName(message);
        parseVariableValue(message);
    }
}
