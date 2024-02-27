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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ExecCmdMessageSSH1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExecCmdMessageSSHv1Parser extends SshMessageParser<ExecCmdMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ExecCmdMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseIgnoreReason(ExecCmdMessageSSH1 message) {
        int lenght = parseIntField(4);
        String debugReason = parseByteString(lenght);
        message.setCommand(debugReason);
    }

    @Override
    protected void parseMessageSpecificContents(ExecCmdMessageSSH1 message) {
        parseIgnoreReason(message);
    }

    @Override
    public void parse(ExecCmdMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
