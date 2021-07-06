/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.message;

import de.rub.nds.sshattacker.core.protocol.preparator.ChannelFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.serializer.ChannelFailureMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.handler.ChannelFailureMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelFailureMessage extends Message<ChannelFailureMessage> {

    @Override
    public ChannelFailureMessageHandler getHandler(SshContext context) {
        return new ChannelFailureMessageHandler(context);
    }

    @Override
    public ChannelFailureMessageSerializer getSerializer() {
        return new ChannelFailureMessageSerializer(this);
    }

    @Override
    public ChannelFailureMessagePreparator getPreparator(SshContext context) {
        return new ChannelFailureMessagePreparator(context, this);
    }

}
