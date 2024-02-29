/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.RsaAuthChallengeMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaAuthChallengeMessageSSHV1Handler
        extends SshMessageHandler<RsaAuthChallengeMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaAuthChallengeMessageSSHV1Handler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(RsaAuthChallengeMessageSSH1 message) {
        LOGGER.info("Recived a RSA Auth Message");
    }
}
