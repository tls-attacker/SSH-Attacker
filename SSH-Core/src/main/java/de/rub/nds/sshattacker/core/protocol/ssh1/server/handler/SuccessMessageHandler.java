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
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.SuccessMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SuccessMessageHandler extends Ssh1MessageHandler<SuccessMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SuccessMessageHandler(SshContext sshContext) {
        super(sshContext);
    }

    @Override
    public void adjustContext(SuccessMessageSSH1 message) {
        LOGGER.info("Recived a Success Message");
    }
}
