/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoRequestMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.holder.AuthenticationPromptEntryParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
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
        int userNameLength = parseIntField();
        message.setUserNameLength(userNameLength);
        LOGGER.debug("User name length: {}", userNameLength);
        String userName = parseByteString(userNameLength);
        message.setUserName(userName);
        LOGGER.debug("User name: {}", () -> backslashEscapeString(userName));
    }

    private void parseInstruction() {
        int instructionLength = parseIntField();
        message.setInstructionLength(instructionLength);
        LOGGER.debug("Instruction length: {}", instructionLength);
        String instruction = parseByteString(instructionLength);
        message.setInstruction(instruction);
        LOGGER.debug("Instruction: {}", () -> backslashEscapeString(instruction));
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField();
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("Language tag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength);
        message.setLanguageTag(languageTag);
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
    }

    private void parsePromptEntries() {
        int promptEntriesCount = parseIntField();
        message.setPromptEntriesCount(promptEntriesCount);
        LOGGER.debug("Number of prompt entries: {}", promptEntriesCount);

        for (int promptEntryIdx = 0, promptEntryStartPointer = getPointer();
                promptEntryIdx < promptEntriesCount;
                promptEntryIdx++, promptEntryStartPointer = getPointer()) {

            AuthenticationPromptEntryParser promptEntryParser =
                    new AuthenticationPromptEntryParser(getArray(), promptEntryStartPointer);

            message.addPromptEntry(promptEntryParser.parse());
            setPointer(promptEntryParser.getPointer());
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
