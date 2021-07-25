/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.IgnoreMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.IgnoreMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.handler.IgnoreMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class IgnoreMessage extends Message<IgnoreMessage> {

    private ModifiableByteArray data;

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public IgnoreMessageHandler getHandler(SshContext context) {
        return new IgnoreMessageHandler(context);
    }

    @Override
    public IgnoreMessageSerializer getSerializer() {
        return new IgnoreMessageSerializer(this);
    }

    @Override
    public IgnoreMessagePreparator getPreparator(SshContext context) {
        return new IgnoreMessagePreparator(context, this);
    }
}
