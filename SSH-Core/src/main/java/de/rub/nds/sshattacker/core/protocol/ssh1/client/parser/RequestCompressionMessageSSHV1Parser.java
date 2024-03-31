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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.RequestCompressionMessageSSH1;
import java.io.InputStream;

public class RequestCompressionMessageSSHV1Parser
        extends Ssh1MessageParser<RequestCompressionMessageSSH1> {

    public RequestCompressionMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseExitStatus(RequestCompressionMessageSSH1 message) {
        int compressionState = parseIntField(4);
        message.setCompressionState(compressionState);
    }

    @Override
    protected void parseMessageSpecificContents(RequestCompressionMessageSSH1 message) {
        parseExitStatus(message);
    }

    @Override
    public void parse(RequestCompressionMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
