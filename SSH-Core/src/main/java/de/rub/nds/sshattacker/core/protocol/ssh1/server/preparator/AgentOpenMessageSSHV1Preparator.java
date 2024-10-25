/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.AgentOpenMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AgentOpenMessageSSHV1Preparator extends Ssh1MessagePreparator<AgentOpenMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AgentOpenMessageSSHV1Preparator(Chooser chooser, AgentOpenMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_SMSG_AGENT_OPEN);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getLocalChannel() == null) {
            getObject().setLocalChannel(0);
        }
        LOGGER.debug(getObject().getLocalChannel().getValue());
    }
}
