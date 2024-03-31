/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ExitStatusMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExitStatusMessageSSHV1Preparator extends Ssh1MessagePreparator<ExitStatusMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExitStatusMessageSSHV1Preparator(Chooser chooser, ExitStatusMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_SMSG_EXITSTATUS);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getExitStatus() == null) {
            getObject().setExitStatus(0);
        }
        LOGGER.debug(getObject().getExitStatus().getValue());
    }
}
