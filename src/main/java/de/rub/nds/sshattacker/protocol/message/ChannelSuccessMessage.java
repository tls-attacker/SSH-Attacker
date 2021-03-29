/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.sshattacker.protocol.handler.ChannelSuccessMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelSuccessMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelSuccessMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelSuccessMessage extends Message<ChannelSuccessMessage> {

    @Override
    public ChannelSuccessMessageHandler getHandler(SshContext context) {
        return new ChannelSuccessMessageHandler(context);
    }

    @Override
    public ChannelSuccessMessageSerializer getSerializer() {
        return new ChannelSuccessMessageSerializer(this);
    }

    @Override
    public ChannelSuccessMessagePreparator getPreparator(SshContext context) {
        return new ChannelSuccessMessagePreparator(context, this);
    }

}
