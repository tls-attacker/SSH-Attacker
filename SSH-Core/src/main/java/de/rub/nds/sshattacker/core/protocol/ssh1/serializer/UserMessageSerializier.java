/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.UserMessageSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserMessageSerializier extends SshMessageSerializer<UserMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserMessageSerializier(UserMessageSSH1 message) {
        super(message);
    }

    private void serializeUsername() {
        LOGGER.debug("Description length: " + message.getUsername().getValue().length());
        appendInt(
                message.getUsername().getValue().length(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: " + message.getUsername().getValue());
        appendString(message.getUsername().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeUsername();
    }
}
