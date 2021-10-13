/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelDataMessageHandler extends Handler<ChannelDataMessage> {

    public ChannelDataMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ChannelDataMessage message) {
        // TODO: Handle ChannelDataMessage
    }
}
