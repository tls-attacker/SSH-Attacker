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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelWindowAdjustMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelWindowAdjustMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelWindowAdjustMessageSerializer;
import java.io.InputStream;

public class ChannelWindowAdjustMessage extends ChannelMessage<ChannelWindowAdjustMessage> {

    private ModifiableInteger bytesToAdd;

    public ModifiableInteger getBytesToAdd() {
        return bytesToAdd;
    }

    public void setBytesToAdd(ModifiableInteger bytesToAdd) {
        this.bytesToAdd = bytesToAdd;
    }

    public void setBytesToAdd(int bytesToAdd) {
        this.bytesToAdd = ModifiableVariableFactory.safelySetValue(this.bytesToAdd, bytesToAdd);
    }

    @Override
    public ChannelWindowAdjustMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelWindowAdjustMessageParser(stream);
    }

    /*    @Override
    public ChannelWindowAdjustMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelWindowAdjustMessageParser(array, startPosition);
    }*/

    @Override
    public ChannelWindowAdjustMessagePreparator getPreparator(SshContext context) {
        return new ChannelWindowAdjustMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelWindowAdjustMessageSerializer getSerializer(SshContext context) {
        return new ChannelWindowAdjustMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "CHANNEL_WINDOW_ADJUST";
    }

    @Override
    public SshMessageHandler<ChannelWindowAdjustMessage> getHandler(SshContext context) {
        return null;
    }
}
