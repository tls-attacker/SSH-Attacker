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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.StdoutDataMessageSSH1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StdoutDataMessageSSHv1Parser extends SshMessageParser<StdoutDataMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public StdoutDataMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseIgnoreReason(StdoutDataMessageSSH1 message) {
        int lenght = parseIntField(4);
        String debugReason = parseByteString(lenght);
        message.setData(debugReason);
    }

    @Override
    protected void parseMessageSpecificContents(StdoutDataMessageSSH1 message) {
        parseIgnoreReason(message);
    }

    @Override
    public void parse(StdoutDataMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
