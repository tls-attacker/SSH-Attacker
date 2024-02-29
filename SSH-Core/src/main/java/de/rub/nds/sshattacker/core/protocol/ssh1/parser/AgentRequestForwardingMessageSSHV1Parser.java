/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AgentRequestForwardingMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.EofMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class AgentRequestForwardingMessageSSHV1Parser extends SshMessageParser<AgentRequestForwardingMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public AgentRequestForwardingMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageSpecificContents(AgentRequestForwardingMessageSSH1 message) {}

    @Override
    public void parse(AgentRequestForwardingMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
