/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.PortForwardRequestMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.X11OpenMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PortForwardRequestMessageSSHV1Preparator extends SshMessagePreparator<PortForwardRequestMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PortForwardRequestMessageSSHV1Preparator(Chooser chooser, PortForwardRequestMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_PORT_FORWARD_REQUEST);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getServerPort() == null) {
            getObject().setServerPort(0);
        }
        LOGGER.debug(getObject().getServerPort().getValue());
    }
}
