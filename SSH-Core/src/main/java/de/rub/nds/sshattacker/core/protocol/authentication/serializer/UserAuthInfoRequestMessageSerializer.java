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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthInfoRequestMessageSerializer
        extends SshMessageSerializer<UserAuthInfoRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthInfoRequestMessageSerializer(UserAuthInfoRequestMessage message) {
        super(message);
    }

    private void serializeUserName() {
        Integer userNameLength = message.getUserNameLength().getValue();
        LOGGER.debug("User name length: {}", userNameLength);
        appendInt(userNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String userName = message.getUserName().getValue();
        LOGGER.debug("User name: {}", () -> backslashEscapeString(userName));
        appendString(userName);
    }

    private void serializeInstruction() {
        Integer instructionLength = message.getInstructionLength().getValue();
        LOGGER.debug("Instruction length: {}", instructionLength);
        appendInt(instructionLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String instruction = message.getInstruction().getValue();
        LOGGER.debug("Instruction: {}", () -> backslashEscapeString(instruction));
        appendString(instruction);
    }

    private void serializeLanguageTag() {
        Integer languageTagLength = message.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = message.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        appendString(languageTag);
    }

    private void serializePrompt() {
        Integer promptEntryCount = message.getPromptEntriesCount().getValue();
        LOGGER.debug("Number of prompt entries: {}", promptEntryCount);
        appendInt(promptEntryCount, DataFormatConstants.UINT32_SIZE);

        message.getPromptEntries()
                .forEach(
                        promptEntry ->
                                appendBytes(
                                        promptEntry.getHandler(null).getSerializer().serialize()));
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeUserName();
        serializeInstruction();
        serializeLanguageTag();
        serializePrompt();
    }
}
