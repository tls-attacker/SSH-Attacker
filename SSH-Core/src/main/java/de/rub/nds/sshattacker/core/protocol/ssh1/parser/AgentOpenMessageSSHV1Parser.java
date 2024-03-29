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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AgentOpenMessageSSH1;
import java.io.InputStream;

public class AgentOpenMessageSSHV1Parser extends SshMessageParser<AgentOpenMessageSSH1> {

    public AgentOpenMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseLocalChannel(AgentOpenMessageSSH1 message) {
        int exitStatus = parseIntField(4);
        message.setLocalChannel(exitStatus);
    }

    @Override
    protected void parseMessageSpecificContents(AgentOpenMessageSSH1 message) {
        parseLocalChannel(message);
    }

    @Override
    public void parse(AgentOpenMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
