/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ExecShellMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ExecShellMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ExecShellMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ExecShellMessageSSHV1Serializier;
import java.io.InputStream;

public class ExecShellMessageSSH1 extends Ssh1Message<ExecShellMessageSSH1> {

    @Override
    public ExecShellMessageSSHV1Handler getHandler(SshContext context) {
        return new ExecShellMessageSSHV1Handler(context);
    }

    @Override
    public Ssh1MessageParser<ExecShellMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new ExecShellMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<ExecShellMessageSSH1> getPreparator(SshContext context) {
        return new ExecShellMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<ExecShellMessageSSH1> getSerializer(SshContext context) {
        return new ExecShellMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EXEC_SHELL";
    }
}
