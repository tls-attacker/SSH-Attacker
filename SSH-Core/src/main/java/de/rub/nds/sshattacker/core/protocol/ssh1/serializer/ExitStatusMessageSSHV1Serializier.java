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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ExitStatusMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExitStatusMessageSSHV1Serializier extends SshMessageSerializer<ExitStatusMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExitStatusMessageSSHV1Serializier(ExitStatusMessageSSH1 message) {
        super(message);
    }

    private void serializeExitStatus() {
        LOGGER.debug("Exit Status: " + message.getExitStatus().getValue());
        appendInt(message.getExitStatus().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExitStatus();
    }
}
