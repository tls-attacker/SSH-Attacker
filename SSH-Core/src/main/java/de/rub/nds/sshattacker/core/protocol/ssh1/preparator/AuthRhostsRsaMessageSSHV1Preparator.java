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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AuthRhostsRsaMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthRhostsRsaMessageSSHV1Preparator
        extends SshMessagePreparator<AuthRhostsRsaMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AuthRhostsRsaMessageSSHV1Preparator(Chooser chooser, AuthRhostsRsaMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_AUTH_RHOSTS_RSA);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
    }
}
