/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationPrompt;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthInfoRequestMessageParser extends SshMessageParser<UserAuthInfoRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthInfoRequestMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthInfoRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UserAuthInfoRequestMessage createMessage() {
        return new UserAuthInfoRequestMessage();
    }

    private void parseUserName() {
        int userNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setUserNameLength(userNameLength);
        LOGGER.debug("User name length: {}", userNameLength);
        String userName = parseByteString(userNameLength);
        message.setUserName(userName);
        LOGGER.debug("User name: {}", () -> backslashEscapeString(userName));
    }

    private void parseInstruction() {
        int instructionLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setInstructionLength(instructionLength);
        LOGGER.debug("Instruction length: {}", instructionLength);
        String instruction = parseByteString(instructionLength);
        message.setInstruction(instruction);
        LOGGER.debug("Instruction: {}", () -> backslashEscapeString(instruction));
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("Language tag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength);
        message.setLanguageTag(languageTag);
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
    }

    private void parsePromptEntries() {
        int promptEntryCount = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setPromptEntryCount(promptEntryCount);
        LOGGER.debug("Number of prompt entries: {}", promptEntryCount);

        for (int i = 0; i < message.getPromptEntryCount().getValue(); i++) {
            AuthenticationPrompt.PromptEntry entry = new AuthenticationPrompt.PromptEntry();
            entry.setPromptLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
            LOGGER.debug("Prompt entry [{}] length: {}", i, entry.getPromptLength().getValue());
            entry.setPrompt(parseByteString(entry.getPromptLength().getValue()));
            LOGGER.debug(
                    "Prompt entry [{}]: {}",
                    i,
                    backslashEscapeString(entry.getPrompt().getValue()));
            byte echo = parseByteField(1);
            entry.setEcho(echo);
            LOGGER.debug("Prompt entry [{}] wants echo:{}", i, Converter.byteToBoolean(echo));

            message.getPrompt().add(entry);
        }
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseUserName();
        parseInstruction();
        parseLanguageTag();
        parsePromptEntries();
    }
}
