/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswdChangeReqMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswdChangeReqMessageParser
        extends SshMessageParser<UserAuthPasswdChangeReqMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPasswdChangeReqMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthPasswdChangeReqMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UserAuthPasswdChangeReqMessage createMessage() {
        return new UserAuthPasswdChangeReqMessage();
    }

    private void parsePrompt() {
        message.setPromptLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Prompt length: {}", message.getPromptLength().getValue());
        message.setPrompt(
                parseByteString(message.getPromptLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Prompt: {}", message.getPrompt().getValue());
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: {}", message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Language tag: {}", message.getLanguageTag().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePrompt();
        parseLanguageTag();
    }
}
