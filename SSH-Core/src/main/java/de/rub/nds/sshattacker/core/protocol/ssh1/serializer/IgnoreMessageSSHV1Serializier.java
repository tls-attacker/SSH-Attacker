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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.IgnoreMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class IgnoreMessageSSHV1Serializier extends SshMessageSerializer<IgnoreMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public IgnoreMessageSSHV1Serializier(IgnoreMessageSSH1 message) {
        super(message);
    }

    private void serializeReason() {
        LOGGER.debug("Description length: " + message.getIgnoreMessage().getValue());
        appendInt(
                message.getIgnoreMessage().getValue().length(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: " + message.getIgnoreMessage().getValue());
        appendString(message.getIgnoreMessage().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeReason();
    }
}
