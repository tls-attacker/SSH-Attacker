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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ChannelOpenConfirmationMessageSSH1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageSSHV1Parser
        extends SshMessageParser<ChannelOpenConfirmationMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

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
