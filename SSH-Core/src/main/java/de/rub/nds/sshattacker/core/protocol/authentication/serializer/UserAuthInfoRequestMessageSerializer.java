/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationPrompt;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthInfoRequestMessageSerializer
        extends SshMessageSerializer<UserAuthInfoRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthInfoRequestMessageSerializer(UserAuthInfoRequestMessage message) {
        super(message);
    }

    private void serializeUserName() {
        LOGGER.debug("User name length: " + message.getUserNameLength().getValue());
        appendInt(message.getUserNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(("User name: " + message.getUserName().getValue()));
        appendString(message.getUserName().getValue());
    }

    private void serializeInstruction() {
        LOGGER.debug("Instruction length: " + message.getInstructionLength().getValue());
        appendInt(
                message.getInstructionLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Instruction: " + message.getInstruction().getValue());
        appendString(message.getInstruction().getValue());
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: " + message.getLanguageTagLength().getValue());
        appendInt(
                message.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Language tag: " + message.getLanguageTag().getValue());
        appendString(message.getLanguageTag().getValue());
    }

    private void serializePrompts() {
        LOGGER.debug("Number of promts: " + message.getNumPrompts().getValue());
        appendInt(message.getNumPrompts().getValue(), DataFormatConstants.UINT32_SIZE);

        for (int i = 0; i < message.getNumPrompts().getValue(); i++) {
            AuthenticationPrompt temp = message.getPrompts().get(i);
            LOGGER.debug("Prompt[" + i + "] length: " + temp.getPromptLength().getValue());
            appendInt(temp.getPromptLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
            LOGGER.debug("Prompt[" + i + "] : " + temp.getPrompt());
            appendString(temp.getPrompt().getValue());
            LOGGER.debug(
                    "Prompt["
                            + i
                            + "] wants echo: "
                            + Converter.byteToBoolean(temp.getEcho().getValue()));
            appendByte(temp.getEcho().getValue());
        }
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeUserName();
        serializeInstruction();
        serializeLanguageTag();
        serializePrompts();
    }
}
