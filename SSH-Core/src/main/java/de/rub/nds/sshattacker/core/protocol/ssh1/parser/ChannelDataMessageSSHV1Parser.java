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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ChannelDataMessageSSH1;
import java.io.InputStream;

public class ChannelDataMessageSSHV1Parser extends Ssh1MessageParser<ChannelDataMessageSSH1> {

    public ChannelDataMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseData(ChannelDataMessageSSH1 message) {
        int remoteChannel = parseIntField(4);
        int dataLenght = parseIntField(4);
        String data = parseByteString(dataLenght);
        message.setRemoteChannel(remoteChannel);
        message.setData(data);
    }

    @Override
    protected void parseMessageSpecificContents(ChannelDataMessageSSH1 message) {
        parseData(message);
    }

    @Override
    public void parse(ChannelDataMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
