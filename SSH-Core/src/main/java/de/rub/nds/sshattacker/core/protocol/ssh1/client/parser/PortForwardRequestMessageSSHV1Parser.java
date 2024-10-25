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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.PortForwardRequestMessageSSH1;
import java.io.InputStream;

public class PortForwardRequestMessageSSHV1Parser
        extends Ssh1MessageParser<PortForwardRequestMessageSSH1> {

    public PortForwardRequestMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseData(PortForwardRequestMessageSSH1 message) {
        int serverPort = parseIntField(4);
        int hostlenght = parseIntField(4);
        String hostToConnect = parseByteString(hostlenght);
        int portToConnect = parseIntField(4);
        message.setServerPort(serverPort);
        message.setHostToConnect(hostToConnect);
        message.setPortToConnect(portToConnect);
    }

    @Override
    protected void parseMessageSpecificContents(PortForwardRequestMessageSSH1 message) {
        parseData(message);
    }

    @Override
    public void parse(PortForwardRequestMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
