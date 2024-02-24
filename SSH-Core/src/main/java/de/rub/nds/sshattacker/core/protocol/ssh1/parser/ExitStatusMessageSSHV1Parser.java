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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ExitStatusMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class ExitStatusMessageSSHV1Parser extends SshMessageParser<ExitStatusMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ExitStatusMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseExitStatus(ExitStatusMessageSSH1 message) {
        int exitStatus = parseIntField(4);
        message.setExitStatus(exitStatus);
    }

    @Override
    protected void parseMessageSpecificContents(ExitStatusMessageSSH1 message) {
        parseExitStatus(message);
    }

    @Override
    public void parse(ExitStatusMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
