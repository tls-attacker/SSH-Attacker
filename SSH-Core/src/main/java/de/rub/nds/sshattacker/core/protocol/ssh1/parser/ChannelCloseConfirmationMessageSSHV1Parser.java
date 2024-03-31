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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ChannelCloseConfirmationMessageSSH1;
import java.io.InputStream;

public class ChannelCloseConfirmationMessageSSHV1Parser
        extends Ssh1MessageParser<ChannelCloseConfirmationMessageSSH1> {

    public ChannelCloseConfirmationMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseExitStatus(ChannelCloseConfirmationMessageSSH1 message) {
        int remoteChannel = parseIntField(4);
        message.setRemoteChannel(remoteChannel);
    }

    @Override
    protected void parseMessageSpecificContents(ChannelCloseConfirmationMessageSSH1 message) {
        parseExitStatus(message);
    }

    @Override
    public void parse(ChannelCloseConfirmationMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
