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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.X11RequestForwardMessageSSH1;
import java.io.InputStream;

public class X11RequestForwardMessageSSHV1Parser
        extends Ssh1MessageParser<X11RequestForwardMessageSSH1> {

    public X11RequestForwardMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseData(X11RequestForwardMessageSSH1 message) {

        int authenticationProtocolLenght = parseIntField(4);
        String authenticationProtocol = parseByteString(authenticationProtocolLenght);
        int authenticationDataLenght = parseIntField(4);
        String authenticationData = parseByteString(authenticationDataLenght);
        int screenNumber = parseIntField(4);
        message.setX11AuthenticationProtocol(authenticationProtocol);
        message.setX11AuthenticationData(authenticationData);
        message.setScreenNumber(screenNumber);
    }

    @Override
    protected void parseMessageSpecificContents(X11RequestForwardMessageSSH1 message) {
        parseData(message);
    }

    @Override
    public void parse(X11RequestForwardMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
