/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.PortForwardRequestMessageSSH1;
import java.io.InputStream;

public class PortForwardRequestMessageSSHV1Parser
        extends SshMessageParser<PortForwardRequestMessageSSH1> {

    public PortForwardRequestMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseData(PortForwardRequestMessageSSH1 message) {
        int remoteChannel = parseIntField(4);
        int dataLenght = parseIntField(4);
        String data = parseByteString(dataLenght);
        int portToConnect = parseIntField(4);
        message.setServerPort(remoteChannel);
        message.setHostToConnect(data);
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
