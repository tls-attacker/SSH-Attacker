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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthInfoRequestMessageSerializer
        extends SshMessageSerializer<UserAuthInfoRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeUserName(
            UserAuthInfoRequestMessage object, SerializerStream output) {
        Integer userNameLength = object.getUserNameLength().getValue();
        LOGGER.debug("User name length: {}", userNameLength);
        output.appendInt(userNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String userName = object.getUserName().getValue();
        LOGGER.debug("User name: {}", () -> backslashEscapeString(userName));
        output.appendString(userName);
    }

    private static void serializeInstruction(
            UserAuthInfoRequestMessage object, SerializerStream output) {
        Integer instructionLength = object.getInstructionLength().getValue();
        LOGGER.debug("Instruction length: {}", instructionLength);
        output.appendInt(instructionLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String instruction = object.getInstruction().getValue();
        LOGGER.debug("Instruction: {}", () -> backslashEscapeString(instruction));
        output.appendString(instruction);
    }

    private static void serializeLanguageTag(
            UserAuthInfoRequestMessage object, SerializerStream output) {
        Integer languageTagLength = object.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        output.appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = object.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        output.appendString(languageTag);
    }

    private static void serializePrompt(
            UserAuthInfoRequestMessage object, SerializerStream output) {
        Integer promptEntryCount = object.getPromptEntriesCount().getValue();
        LOGGER.debug("Number of prompt entries: {}", promptEntryCount);
        output.appendInt(promptEntryCount, DataFormatConstants.UINT32_SIZE);

        object.getPromptEntries()
                .forEach(promptEntry -> output.appendBytes(promptEntry.serialize()));
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthInfoRequestMessage object, SerializerStream output) {
        serializeUserName(object, output);
        serializeInstruction(object, output);
        serializeLanguageTag(object, output);
        serializePrompt(object, output);
    }
}
