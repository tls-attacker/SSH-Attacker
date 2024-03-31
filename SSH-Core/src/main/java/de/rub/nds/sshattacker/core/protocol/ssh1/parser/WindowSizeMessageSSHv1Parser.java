/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.WindowSizeMessageSSH1;
import java.io.InputStream;

public class WindowSizeMessageSSHv1Parser extends Ssh1MessageParser<WindowSizeMessageSSH1> {

    public WindowSizeMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageSpecificContents(WindowSizeMessageSSH1 message) {

        int hightRows = parseIntField(4);
        int widthColumns = parseIntField(4);
        int widthPixel = parseIntField(4);
        int hightPixel = parseIntField(4);

        message.setHightRows(hightRows);
        message.setWidthColumns(widthColumns);
        message.setWidthPixel(widthPixel);
        message.setHightPixel(hightPixel);
    }

    @Override
    public void parse(WindowSizeMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
