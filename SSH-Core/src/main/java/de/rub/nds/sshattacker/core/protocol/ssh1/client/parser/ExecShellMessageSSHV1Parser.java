/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.ExecShellMessageSSH1;
import java.io.InputStream;

public class ExecShellMessageSSHV1Parser extends Ssh1MessageParser<ExecShellMessageSSH1> {

    public ExecShellMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageSpecificContents(ExecShellMessageSSH1 message) {}

    @Override
    public void parse(ExecShellMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
