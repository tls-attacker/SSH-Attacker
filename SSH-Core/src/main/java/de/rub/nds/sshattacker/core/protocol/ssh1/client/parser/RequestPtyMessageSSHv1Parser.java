/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.RequestPtyMessageSSH1;
import java.io.InputStream;

public class RequestPtyMessageSSHv1Parser extends Ssh1MessageParser<RequestPtyMessageSSH1> {

    public RequestPtyMessageSSHv1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageSpecificContents(RequestPtyMessageSSH1 message) {

        int termEnvLenght = parseIntField(4);
        String termEnvironment = parseByteString(termEnvLenght);
        message.setTermEnvironment(termEnvironment);

        int hightRows = parseIntField(4);
        int widthColumns = parseIntField(4);
        int widthPixel = parseIntField(4);
        int hightPixel = parseIntField(4);

        message.setHightRows(hightRows);
        message.setWidthColumns(widthColumns);
        message.setWidthPixel(widthPixel);
        message.setHightPixel(hightPixel);

        int ttyModes = parseIntField(4);
        message.setTtyModes(ttyModes);
    }

    @Override
    public void parse(RequestPtyMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
