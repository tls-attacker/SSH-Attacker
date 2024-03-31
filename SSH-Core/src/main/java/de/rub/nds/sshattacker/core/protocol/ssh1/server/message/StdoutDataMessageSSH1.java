/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.handler.StdoutDataMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.parser.StdoutDataMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.preparator.StdoutDataMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.serializer.StdoutDataMessageSSHV1Serializier;
import java.io.InputStream;

public class StdoutDataMessageSSH1 extends Ssh1Message<StdoutDataMessageSSH1> {

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
    public StdoutDataMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new StdoutDataMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<StdoutDataMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new StdoutDataMessageSSHv1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<StdoutDataMessageSSH1> getPreparator(SshContext sshContext) {
        return new StdoutDataMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<StdoutDataMessageSSH1> getSerializer(SshContext sshContext) {
        return new StdoutDataMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_SMSG_STDOUT_DATA";
    }
}
