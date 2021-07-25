/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IgnoreMessageHandler extends Handler<IgnoreMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public IgnoreMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(IgnoreMessage msg) {
        LOGGER.debug("IgnoreMessage retrieved from remote, data: " + msg.getData().getValue());
    }

}
