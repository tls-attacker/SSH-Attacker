/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelFailureMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelFailureMessage extends ChannelMessage<ChannelFailureMessage> {

    public ChannelFailureMessage() {
        super(MessageIDConstant.SSH_MSG_CHANNEL_FAILURE);
    }

    @Override
    public ChannelFailureMessageHandler getHandler(SshContext context) {
        return new ChannelFailureMessageHandler(context, this);
    }
}
