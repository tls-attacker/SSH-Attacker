/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEnvMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestEnvMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestEnvMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeVariableName(
            ChannelRequestEnvMessage object, SerializerStream output) {
        Integer variableNameLength = object.getVariableNameLength().getValue();
        LOGGER.debug("Variable name length: {}", variableNameLength);
        output.appendInt(variableNameLength);
        String variableName = object.getVariableName().getValue();
        LOGGER.debug("Variable name: {}", () -> backslashEscapeString(variableName));
        output.appendString(variableName, StandardCharsets.UTF_8);
    }

    private static void serializeVariableValue(
            ChannelRequestEnvMessage object, SerializerStream output) {
        Integer variableValueLength = object.getVariableValueLength().getValue();
        LOGGER.debug("Variable value length: {}", variableValueLength);
        output.appendInt(variableValueLength);
        String variableValue = object.getVariableValue().getValue();
        LOGGER.debug("Variable value: {}", () -> backslashEscapeString(variableValue));
        output.appendString(variableValue, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestEnvMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeVariableName(object, output);
        serializeVariableValue(object, output);
    }
}
