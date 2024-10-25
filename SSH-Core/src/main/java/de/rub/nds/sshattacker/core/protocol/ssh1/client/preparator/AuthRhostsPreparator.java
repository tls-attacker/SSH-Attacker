/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.AuthRhostsSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthRhostsPreparator extends Ssh1MessagePreparator<AuthRhostsSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AuthRhostsPreparator(Chooser chooser, AuthRhostsSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_AUTH_RHOSTS);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");

        if (getObject().getClientside_username() == null) {
            getObject().setClientside_username("DummyValue");
        }
        LOGGER.debug(getObject().getClientside_username().getValue());
    }
}
