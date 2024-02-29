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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.X11RequestForwardMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X11RequestForwardMessageSSHV1Preparator
        extends SshMessagePreparator<X11RequestForwardMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X11RequestForwardMessageSSHV1Preparator(
            Chooser chooser, X11RequestForwardMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_X11_REQUEST_FORWARDING);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getScreenNumber() == null) {
            getObject().setScreenNumber(0);
        }
        LOGGER.debug(getObject().getScreenNumber().getValue());
    }
}
