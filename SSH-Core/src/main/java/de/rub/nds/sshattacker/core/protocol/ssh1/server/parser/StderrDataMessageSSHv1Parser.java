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
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.StderrDataMessageSSH1;
import java.io.InputStream;

public class StderrDataMessageSSHv1Parser extends Ssh1MessageParser<StderrDataMessageSSH1> {

    public StderrDataMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseIgnoreReason(StderrDataMessageSSH1 message) {
        int lenght = parseIntField(4);
        String errorData = parseByteString(lenght);
        message.setErrorData(errorData);
    }

    @Override
    protected void parseMessageSpecificContents(StderrDataMessageSSH1 message) {
        parseIgnoreReason(message);
    }

    @Override
    public void parse(StderrDataMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
