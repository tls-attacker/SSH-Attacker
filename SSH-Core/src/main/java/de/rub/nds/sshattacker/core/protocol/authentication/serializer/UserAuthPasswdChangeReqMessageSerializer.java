/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswdChangeReqMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswdChangeReqMessageSerializer
        extends SshMessageSerializer<UserAuthPasswdChangeReqMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPasswdChangeReqMessageSerializer(UserAuthPasswdChangeReqMessage message) {
        super(message);
    }

    private void serializePrompt() {
        LOGGER.debug("Prompt length: {}", message.getPromptLength().getValue());
        appendInt(message.getPromptLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Prompt: {}", message.getPrompt().getValue());
        appendString(message.getPrompt().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: {}", message.getLanguageTagLength().getValue());
        appendInt(
                message.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Language tag: {}", message.getLanguageTag().getValue());
        appendString(message.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializePrompt();
        serializeLanguageTag();
    }
}
