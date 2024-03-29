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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.DisconnectMessageSSH1;
import java.io.InputStream;

public class DisconnectMessageParser extends SshMessageParser<DisconnectMessageSSH1> {

    public DisconnectMessageParser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseDisconnectReason(DisconnectMessageSSH1 message) {
        int lenght = parseIntField(4);
        String disconnectReason = parseByteString(lenght);
        message.setDisconnectReason(disconnectReason);
    }

    @Override
    protected void parseMessageSpecificContents(DisconnectMessageSSH1 message) {
        parseDisconnectReason(message);
    }

    @Override
    public void parse(DisconnectMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
