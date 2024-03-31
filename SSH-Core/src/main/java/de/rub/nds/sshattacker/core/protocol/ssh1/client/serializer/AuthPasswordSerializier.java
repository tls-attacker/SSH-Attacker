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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.AuthPasswordSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthPasswordSerializier extends Ssh1MessageSerializer<AuthPasswordSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AuthPasswordSerializier(AuthPasswordSSH1 message) {
        super(message);
    }

    private void serializeReason() {
        LOGGER.debug("Password length: {}", message.getPassword().getValue());
        appendInt(
                message.getPassword().getValue().length(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Password: {}", message.getPassword().getValue());
        appendString(message.getPassword().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeReason();
    }
}
