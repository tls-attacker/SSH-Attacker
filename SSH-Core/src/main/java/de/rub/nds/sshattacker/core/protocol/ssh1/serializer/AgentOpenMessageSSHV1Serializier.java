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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AgentOpenMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ExitStatusMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AgentOpenMessageSSHV1Serializier extends SshMessageSerializer<AgentOpenMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AgentOpenMessageSSHV1Serializier(AgentOpenMessageSSH1 message) {
        super(message);
    }

    private void serializeExitStatus() {
        LOGGER.debug("Agent opening on local channel {}", message.getLocalChannel().getValue());
        appendInt(message.getLocalChannel().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExitStatus();
    }
}
