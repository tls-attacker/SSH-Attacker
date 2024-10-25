/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.ExitStatusMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExitStatusMessageSSHV1Handler extends Ssh1MessageHandler<ExitStatusMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExitStatusMessageSSHV1Handler(SshContext sshContext) {
        super(sshContext);
    }

    @Override
    public void adjustContext(ExitStatusMessageSSH1 message) {
        LOGGER.warn("Recieved Exit Status {}", message.getExitStatus().getValue());
    }
}
