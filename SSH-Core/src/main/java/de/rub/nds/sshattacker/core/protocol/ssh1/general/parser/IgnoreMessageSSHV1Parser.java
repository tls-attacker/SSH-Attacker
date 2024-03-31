/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.general.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.IgnoreMessageSSH1;
import java.io.InputStream;

public class IgnoreMessageSSHV1Parser extends Ssh1MessageParser<IgnoreMessageSSH1> {
    public IgnoreMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseIgnoreMessage(IgnoreMessageSSH1 message) {
        int lenght = parseIntField(4);
        String ignoreMsg = parseByteString(lenght);
        message.setIgnoreReason(ignoreMsg);
    }

    @Override
    protected void parseMessageSpecificContents(IgnoreMessageSSH1 message) {
        parseIgnoreMessage(message);
    }

    @Override
    public void parse(IgnoreMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
