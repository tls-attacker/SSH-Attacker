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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestBreakMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestBreakMessage extends ChannelRequestMessage<ChannelRequestBreakMessage> {

    private ModifiableInteger breakLength;

    public ChannelRequestBreakMessage() {
        super();
    }

    public ChannelRequestBreakMessage(ChannelRequestBreakMessage other) {
        super(other);
        breakLength = other.breakLength != null ? other.breakLength.createCopy() : null;
    }

    @Override
    public ChannelRequestBreakMessage createCopy() {
        return new ChannelRequestBreakMessage(this);
    }

    public ModifiableInteger getBreakLength() {
        return breakLength;
    }

    public void setBreakLength(ModifiableInteger breakLength) {
        this.breakLength = breakLength;
    }

    public void setBreakLength(int breakLength) {
        this.breakLength = ModifiableVariableFactory.safelySetValue(this.breakLength, breakLength);
    }

    @Override
    public ChannelRequestBreakMessageHandler getHandler(SshContext context) {
        return new ChannelRequestBreakMessageHandler(context, this);
    }
}
