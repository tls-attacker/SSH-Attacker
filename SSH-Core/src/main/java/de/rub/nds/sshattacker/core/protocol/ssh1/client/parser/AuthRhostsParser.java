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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.AuthRhostsSSH1;
import java.io.InputStream;

public class AuthRhostsParser extends Ssh1MessageParser<AuthRhostsSSH1> {

    public AuthRhostsParser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseClientSideUsername(AuthRhostsSSH1 message) {
        int lenght = parseIntField(4);
        String clientSideUsername = parseByteString(lenght);
        message.setClientside_username(clientSideUsername);
    }

    @Override
    protected void parseMessageSpecificContents(AuthRhostsSSH1 message) {
        parseClientSideUsername(message);
    }

    @Override
    public void parse(AuthRhostsSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
