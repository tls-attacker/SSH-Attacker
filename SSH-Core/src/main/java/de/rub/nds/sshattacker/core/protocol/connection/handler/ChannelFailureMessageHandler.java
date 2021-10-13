/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelFailureMessageHandler extends Handler<ChannelFailureMessage> {

    public ChannelFailureMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ChannelFailureMessage message) {
        // TODO: Handle ChannelFailureMessage
    }
}
