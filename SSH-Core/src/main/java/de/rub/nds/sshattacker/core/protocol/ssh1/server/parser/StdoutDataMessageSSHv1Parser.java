/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.StdoutDataMessageSSH1;
import java.io.InputStream;

public class StdoutDataMessageSSHv1Parser extends Ssh1MessageParser<StdoutDataMessageSSH1> {
    public StdoutDataMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseStdoutData(StdoutDataMessageSSH1 message) {
        int lenght = parseIntField(4);
        String stdoutData = parseByteString(lenght);
        message.setData(stdoutData);
    }

    @Override
    protected void parseMessageSpecificContents(StdoutDataMessageSSH1 message) {
        parseStdoutData(message);
    }

    @Override
    public void parse(StdoutDataMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
