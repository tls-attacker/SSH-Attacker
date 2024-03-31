/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.AgentRequestForwardingMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.AgentRequestForwardingMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.AgentRequestForwardingMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.AgentRequestForwardingMessageSSHV1Serializier;
import java.io.InputStream;

public class AgentRequestForwardingMessageSSH1
        extends Ssh1Message<AgentRequestForwardingMessageSSH1> {

    @Override
    public AgentRequestForwardingMessageSSHV1Handler getHandler(SshContext context) {
        return new AgentRequestForwardingMessageSSHV1Handler(context);
    }

    @Override
    public Ssh1MessageParser<AgentRequestForwardingMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new AgentRequestForwardingMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<AgentRequestForwardingMessageSSH1> getPreparator(
            SshContext context) {
        return new AgentRequestForwardingMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<AgentRequestForwardingMessageSSH1> getSerializer(
            SshContext context) {
        return new AgentRequestForwardingMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EOF";
    }
}
