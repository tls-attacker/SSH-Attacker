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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.DebugMessageSSH1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugMessageSSHv1Parser extends SshMessageParser<DebugMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public DebugMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseDebugMessage(DebugMessageSSH1 message) {
        int lenght = parseIntField(4);
        String debugReason = parseByteString(lenght);
        message.setDebugMessage(debugReason);
    }

    @Override
    protected void parseMessageSpecificContents(DebugMessageSSH1 message) {
        parseDebugMessage(message);
    }

    @Override
    public void parse(DebugMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
