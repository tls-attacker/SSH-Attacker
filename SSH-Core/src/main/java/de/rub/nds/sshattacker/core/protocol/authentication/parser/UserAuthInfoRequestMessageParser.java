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
        message.setUserNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("User name length: {}", message.getUserNameLength().getValue());
        message.setUserName(parseByteString(message.getUserNameLength().getValue()));
        LOGGER.debug(
                "User name: {}", () -> backslashEscapeString(message.getUserName().getValue()));
    }

    private void parseInstruction() {
        message.setInstructionLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Instruction length: {}", message.getInstructionLength().getValue());
        message.setInstruction(parseByteString(message.getInstructionLength().getValue()));
        LOGGER.debug(
                "Instruction: {}",
                () -> backslashEscapeString(message.getInstruction().getValue()));
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: {}", message.getLanguageTagLength().getValue());
        message.setLanguageTag(parseByteString(message.getLanguageTagLength().getValue()));
        LOGGER.debug(
                "Language tag: {}",
                () -> backslashEscapeString(message.getLanguageTag().getValue()));
    }

    private void parsePromptEntries() {
        message.setPromptEntryCount(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Number of prompt entries: {}", message.getPromptEntryCount().getValue());

        for (int i = 0; i < message.getPromptEntryCount().getValue(); i++) {
            AuthenticationPrompt.PromptEntry entry = new AuthenticationPrompt.PromptEntry();
            entry.setPromptLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
            LOGGER.debug("Prompt entry [{}] length: {}", i, entry.getPromptLength().getValue());
            entry.setPrompt(parseByteString(entry.getPromptLength().getValue()));
            LOGGER.debug(
                    "Prompt entry [{}]: {}",
                    i,
                    backslashEscapeString(entry.getPrompt().getValue()));
            entry.setEcho(parseByteField(1));
            LOGGER.debug(
                    "Prompt entry [{}] wants echo:{}",
                    i,
                    Converter.byteToBoolean(entry.getEcho().getValue()));

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
