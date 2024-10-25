/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.StdinDataMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.StdinDataMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.StdinDataMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.StdinDataMessageSSHV1Serializier;
import java.io.InputStream;

public class StdinDataMessageSSH1 extends Ssh1Message<StdinDataMessageSSH1> {

    private ModifiableString data;

    public ModifiableString getData() {
        return data;
    }

    public void setData(ModifiableString disconnectReason) {
        data = disconnectReason;
    }

    public void setData(String disconnectReason) {
        data = ModifiableVariableFactory.safelySetValue(data, disconnectReason);
    }

    @Override
    public StdinDataMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new StdinDataMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<StdinDataMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new StdinDataMessageSSHv1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<StdinDataMessageSSH1> getPreparator(SshContext sshContext) {
        return new StdinDataMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<StdinDataMessageSSH1> getSerializer(SshContext sshContext) {
        return new StdinDataMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_STDIN_DATA";
    }
}
