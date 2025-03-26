/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenConfirmationMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenConfirmationMessage extends ChannelMessage<ChannelOpenConfirmationMessage> {

    private ModifiableInteger senderChannelId;
    private ModifiableInteger initialWindowSize;
    private ModifiableInteger maximumPacketSize;

    public ModifiableInteger getSenderChannelId() {
        return senderChannelId;
    }

    public void setSenderChannelId(ModifiableInteger senderChannelId) {
        this.senderChannelId = senderChannelId;
    }

    public void setSenderChannelId(int modSenderChannel) {
        senderChannelId =
                ModifiableVariableFactory.safelySetValue(senderChannelId, modSenderChannel);
    }

    public ModifiableInteger getInitialWindowSize() {
        return initialWindowSize;
    }

    public void setInitialWindowSize(ModifiableInteger initialWindowSize) {
        this.initialWindowSize = initialWindowSize;
    }

    public void setInitialWindowSize(int initialWindowSize) {
        this.initialWindowSize =
                ModifiableVariableFactory.safelySetValue(this.initialWindowSize, initialWindowSize);
    }

    public ModifiableInteger getMaximumPacketSize() {
        return maximumPacketSize;
    }

    public void setMaximumPacketSize(ModifiableInteger maximumPacketSize) {
        this.maximumPacketSize = maximumPacketSize;
    }

    public void setMaximumPacketSize(int maximumPacketSize) {
        this.maximumPacketSize =
                ModifiableVariableFactory.safelySetValue(this.maximumPacketSize, maximumPacketSize);
    }

    @Override
    public ChannelOpenConfirmationMessageHandler getHandler(SshContext context) {
        return new ChannelOpenConfirmationMessageHandler(context, this);
    }
}
