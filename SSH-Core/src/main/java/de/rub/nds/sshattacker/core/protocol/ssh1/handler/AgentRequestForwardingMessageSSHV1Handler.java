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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AgentRequestForwardingMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AgentRequestForwardingMessageSSHV1Handler
        extends SshMessageHandler<AgentRequestForwardingMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AgentRequestForwardingMessageSSHV1Handler(SshContext context) {
        super(context);
    }

    /*public HybridKeyExchangeReplyMessageHandler(
            SshContext context, HybridKeyExchangeReplyMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(AgentRequestForwardingMessageSSH1 message) {
        LOGGER.info("Recived a EOF Message");
    }
}
