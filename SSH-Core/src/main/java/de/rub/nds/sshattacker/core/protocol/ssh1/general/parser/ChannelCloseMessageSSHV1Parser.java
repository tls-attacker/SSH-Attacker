/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.general.parser;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.ChannelCloseMessageSSH1;
import java.io.InputStream;

public class ChannelCloseMessageSSHV1Parser extends Ssh1MessageParser<ChannelCloseMessageSSH1> {

    public ChannelCloseMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseExitStatus(ChannelCloseMessageSSH1 message) {
        int remoteChannel = parseIntField(4);
        message.setRemoteChannel(remoteChannel);
    }

    @Override
    protected void parseMessageSpecificContents(ChannelCloseMessageSSH1 message) {
        parseExitStatus(message);
    }

    @Override
    public void parse(ChannelCloseMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
