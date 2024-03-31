/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.StdinDataMessageSSH1;
import java.io.InputStream;

public class StdinDataMessageSSHv1Parser extends Ssh1MessageParser<StdinDataMessageSSH1> {

    public StdinDataMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseIgnoreReason(StdinDataMessageSSH1 message) {
        int lenght = parseIntField(4);
        String debugReason = parseByteString(lenght);
        message.setData(debugReason);
    }

    @Override
    protected void parseMessageSpecificContents(StdinDataMessageSSH1 message) {
        parseIgnoreReason(message);
    }

    @Override
    public void parse(StdinDataMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
