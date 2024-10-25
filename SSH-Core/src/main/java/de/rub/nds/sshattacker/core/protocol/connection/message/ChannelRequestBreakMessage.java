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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestBreakMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestBreakMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestBreakMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestBreakMessageSerializer;
import java.io.InputStream;

public class ChannelRequestBreakMessage extends ChannelRequestMessage<ChannelRequestBreakMessage> {

    private ModifiableInteger breakLength;

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
        return new ChannelRequestBreakMessageHandler(context);
    }

    @Override
    public ChannelRequestBreakMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelRequestBreakMessageParser(stream);
    }

    @Override
    public ChannelRequestBreakMessagePreparator getPreparator(SshContext context) {
        return new ChannelRequestBreakMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelRequestBreakMessageSerializer getSerializer(SshContext context) {
        return new ChannelRequestBreakMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "CHAN_REQ_BREAK";
    }
}
