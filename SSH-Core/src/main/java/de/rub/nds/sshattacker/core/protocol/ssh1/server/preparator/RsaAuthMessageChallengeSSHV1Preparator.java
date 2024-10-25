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
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.RsaAuthChallengeMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaAuthMessageChallengeSSHV1Preparator
        extends Ssh1MessagePreparator<RsaAuthChallengeMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaAuthMessageChallengeSSHV1Preparator(
            Chooser chooser, RsaAuthChallengeMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_SMSG_AUTH_RSA_CHALLENGE);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
    }
}
