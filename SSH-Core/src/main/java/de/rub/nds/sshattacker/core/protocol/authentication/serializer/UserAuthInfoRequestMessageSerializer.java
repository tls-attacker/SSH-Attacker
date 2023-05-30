/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

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
        LOGGER.debug("User name length: {}", message.getUserNameLength().getValue());
        appendInt(message.getUserNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("User name: {}", backslashEscapeString(message.getUserName().getValue()));
        appendString(message.getUserName().getValue());
    }

    private void serializeInstruction() {
        LOGGER.debug("Instruction length: {}", message.getInstructionLength().getValue());
        appendInt(
                message.getInstructionLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Instruction: {}", backslashEscapeString(message.getInstruction().getValue()));
        appendString(message.getInstruction().getValue());
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: {}", message.getLanguageTagLength().getValue());
        appendInt(
                message.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Language tag: {}", backslashEscapeString(message.getLanguageTag().getValue()));
        appendString(message.getLanguageTag().getValue());
    }

    private void serializePrompt() {
        LOGGER.debug("Number of prompt entries: {}", message.getPromptEntryCount().getValue());
        appendInt(message.getPromptEntryCount().getValue(), DataFormatConstants.UINT32_SIZE);

        for (int i = 0; i < message.getPromptEntryCount().getValue(); i++) {
            AuthenticationPrompt.PromptEntry entry = message.getPrompt().get(i);
            LOGGER.debug("Prompt entry [{}] length: {}", i, entry.getPromptLength().getValue());
            appendInt(entry.getPromptLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
            LOGGER.debug("Prompt entry [{}]: {}", i, entry.getPrompt());
            appendString(entry.getPrompt().getValue());
            LOGGER.debug(
                    "Prompt entry [{}] wants echo: {}",
                    i,
                    Converter.byteToBoolean(entry.getEcho().getValue()));
            appendByte(entry.getEcho().getValue());
        }
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeUserName();
        serializeInstruction();
        serializeLanguageTag();
        serializePrompt();
    }
}
