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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.StderrDataMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.StdoutDataMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class StderrDataMessageSSHv1Parser extends SshMessageParser<StderrDataMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();
    public StderrDataMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseIgnoreReason(StderrDataMessageSSH1 message) {
        int lenght = parseIntField(4);
        String debugReason = parseByteString(lenght);
        message.setData(debugReason);
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
