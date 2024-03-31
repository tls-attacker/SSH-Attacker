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
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.ChannelOpenConfirmationMessageSSH1;
import java.io.InputStream;

public class ChannelOpenConfirmationMessageSSHV1Parser
        extends Ssh1MessageParser<ChannelOpenConfirmationMessageSSH1> {

    public ChannelOpenConfirmationMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseChannel(ChannelOpenConfirmationMessageSSH1 message) {
        int remoteChannel = parseIntField(4);
        int localChannel = parseIntField(4);
        message.setRemoteChannel(remoteChannel);
        message.setLocalChannel(localChannel);
    }

    @Override
    protected void parseMessageSpecificContents(ChannelOpenConfirmationMessageSSH1 message) {
        parseChannel(message);
    }

    @Override
    public void parse(ChannelOpenConfirmationMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
