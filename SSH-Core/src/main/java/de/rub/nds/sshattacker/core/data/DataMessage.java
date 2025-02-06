/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;

public abstract class DataMessage<T extends DataMessage<T>> extends ProtocolMessage<T> {

    // Wrapper that was used when receiving or sending this message.
    private ChannelDataMessage channelDataWrapper;

    protected DataMessage() {
        super();
    }

    protected DataMessage(DataMessage<T> other) {
        super(other);
        channelDataWrapper =
                other.channelDataWrapper != null ? other.channelDataWrapper.createCopy() : null;
    }

    @Override
    public abstract DataMessage<T> createCopy();

    public ChannelDataMessage getChannelDataWrapper() {
        return channelDataWrapper;
    }

    public void setChannelDataWrapper(ChannelDataMessage channelDataWrapper) {
        this.channelDataWrapper = channelDataWrapper;
    }
}
