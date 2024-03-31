/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.AuthRhostsSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthRhostsSerializier extends Ssh1MessageSerializer<AuthRhostsSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AuthRhostsSerializier(AuthRhostsSSH1 message) {
        super(message);
    }

    private void serializeReason() {
        LOGGER.debug("Description length: {}", message.getClientside_username().getValue());
        appendInt(
                message.getClientside_username().getValue().length(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: {}", message.getClientside_username().getValue());
        appendString(message.getClientside_username().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeReason();
    }
}
