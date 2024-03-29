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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.SuccessMessageSSH1;
import java.io.InputStream;

public class SuccessMessageParser extends SshMessageParser<SuccessMessageSSH1> {

    public SuccessMessageParser(SshContext context, InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageSpecificContents(SuccessMessageSSH1 message) {}

    @Override
    public void parse(SuccessMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
