/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.general.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.DebugMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugMessageSSHV1Preparator extends Ssh1MessagePreparator<DebugMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugMessageSSHV1Preparator(Chooser chooser, DebugMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_MSG_DEBUG);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getDebugMessage() == null) {
            getObject().setDebugMessage("DummyValue");
        }
        LOGGER.debug(getObject().getDebugMessage().getValue());
    }
}
