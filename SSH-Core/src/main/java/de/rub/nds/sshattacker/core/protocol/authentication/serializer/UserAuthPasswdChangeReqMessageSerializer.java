/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswdChangeReqMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswdChangeReqMessageSerializer
        extends SshMessageSerializer<UserAuthPasswdChangeReqMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializePrompt(
            UserAuthPasswdChangeReqMessage object, SerializerStream output) {
        LOGGER.debug("Prompt length: {}", object.getPromptLength().getValue());
        output.appendInt(object.getPromptLength().getValue());
        LOGGER.debug("Prompt: {}", object.getPrompt().getValue());
        output.appendString(object.getPrompt().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializeLanguageTag(
            UserAuthPasswdChangeReqMessage object, SerializerStream output) {
        LOGGER.debug("Language tag length: {}", object.getLanguageTagLength().getValue());
        output.appendInt(object.getLanguageTagLength().getValue());
        LOGGER.debug("Language tag: {}", object.getLanguageTag().getValue());
        output.appendString(object.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthPasswdChangeReqMessage object, SerializerStream output) {
        serializePrompt(object, output);
        serializeLanguageTag(object, output);
    }
}
