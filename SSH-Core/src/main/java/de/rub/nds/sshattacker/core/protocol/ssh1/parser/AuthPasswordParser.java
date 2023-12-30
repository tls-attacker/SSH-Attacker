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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AuthPasswordSSH1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthPasswordParser extends SshMessageParser<AuthPasswordSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public AuthPasswordParser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parsePassword(AuthPasswordSSH1 message) {
        int lenght = parseIntField(4);
        String password = parseByteString(lenght);
        message.setPassword(password);
    }

    @Override
    protected void parseMessageSpecificContents(AuthPasswordSSH1 message) {
        parsePassword(message);
    }

    @Override
    public void parse(AuthPasswordSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
