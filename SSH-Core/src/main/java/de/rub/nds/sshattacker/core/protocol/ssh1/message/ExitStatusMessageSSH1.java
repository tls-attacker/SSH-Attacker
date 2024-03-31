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
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ExitStatusMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ExitStatusMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ExitStatusMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ExitStatusMessageSSHV1Serializier;
import java.io.InputStream;

public class ExitStatusMessageSSH1 extends Ssh1Message<ExitStatusMessageSSH1> {

    private ModifiableInteger exitStatus;

    public ModifiableInteger getExitStatus() {
        return exitStatus;
    }

    public void setExitStatus(ModifiableInteger exitStatus) {
        this.exitStatus = exitStatus;
    }

    public void setExitStatus(int exitStatus) {
        this.exitStatus = ModifiableVariableFactory.safelySetValue(this.exitStatus, exitStatus);
    }

    @Override
    public ExitStatusMessageSSHV1Handler getHandler(SshContext context) {
        return new ExitStatusMessageSSHV1Handler(context);
    }

    @Override
    public Ssh1MessageParser<ExitStatusMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new ExitStatusMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<ExitStatusMessageSSH1> getPreparator(SshContext context) {
        return new ExitStatusMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<ExitStatusMessageSSH1> getSerializer(SshContext context) {
        return new ExitStatusMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EOF";
    }
}
