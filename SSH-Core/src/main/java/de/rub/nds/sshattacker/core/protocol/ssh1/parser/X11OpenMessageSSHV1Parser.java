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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.X11OpenMessageSSH1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X11OpenMessageSSHV1Parser extends SshMessageParser<X11OpenMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public X11OpenMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseData(X11OpenMessageSSH1 message) {
        int remoteChannel = parseIntField(4);
        int dataLenght = parseIntField(4);
        String data = parseByteString(dataLenght);
        message.setLocalChannel(remoteChannel);
        message.setOriginatorString(data);
    }

    @Override
    protected void parseMessageSpecificContents(X11OpenMessageSSH1 message) {
        parseData(message);
    }

    @Override
    public void parse(X11OpenMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
