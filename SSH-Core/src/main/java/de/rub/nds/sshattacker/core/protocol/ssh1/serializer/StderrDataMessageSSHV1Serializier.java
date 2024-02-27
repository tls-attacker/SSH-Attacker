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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.StderrDataMessageSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StderrDataMessageSSHV1Serializier extends SshMessageSerializer<StderrDataMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StderrDataMessageSSHV1Serializier(StderrDataMessageSSH1 message) {
        super(message);
    }

    private void serializeReason() {
        LOGGER.debug("Description length: " + message.getData().getValue());
        appendInt(message.getData().getValue().length(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: " + message.getData().getValue());
        appendString(message.getData().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeReason();
    }
}
