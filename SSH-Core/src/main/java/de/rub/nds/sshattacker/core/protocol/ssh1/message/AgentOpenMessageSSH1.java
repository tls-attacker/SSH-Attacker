/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.AgentOpenMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.AgentOpenMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.AgentOpenMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.AgentOpenMessageSSHV1Serializier;
import java.io.InputStream;

public class AgentOpenMessageSSH1 extends Ssh1Message<AgentOpenMessageSSH1> {

    private ModifiableInteger localChannel;

    public ModifiableInteger getLocalChannel() {
        return localChannel;
    }

    public void setLocalChannel(ModifiableInteger localChannel) {
        this.localChannel = localChannel;
    }

    public void setLocalChannel(int localChannel) {
        this.localChannel =
                ModifiableVariableFactory.safelySetValue(this.localChannel, localChannel);
    }

    @Override
    public AgentOpenMessageSSHV1Handler getHandler(SshContext context) {
        return new AgentOpenMessageSSHV1Handler(context);
    }

    @Override
    public Ssh1MessageParser<AgentOpenMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new AgentOpenMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<AgentOpenMessageSSH1> getPreparator(SshContext context) {
        return new AgentOpenMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<AgentOpenMessageSSH1> getSerializer(SshContext context) {
        return new AgentOpenMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EOF";
    }
}
