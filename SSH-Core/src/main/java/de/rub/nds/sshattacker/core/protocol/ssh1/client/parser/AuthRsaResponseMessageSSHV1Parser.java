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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.AuthRsaResponseMessageSSH1;
import java.io.InputStream;

public class AuthRsaResponseMessageSSHV1Parser
        extends Ssh1MessageParser<AuthRsaResponseMessageSSH1> {

    public AuthRsaResponseMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseExitStatus(AuthRsaResponseMessageSSH1 message) {
        int exitStatus = parseIntField(2);
        message.setMd5Response(exitStatus);
    }

    @Override
    protected void parseMessageSpecificContents(AuthRsaResponseMessageSSH1 message) {
        parseExitStatus(message);
    }

    @Override
    public void parse(AuthRsaResponseMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
