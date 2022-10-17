/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestUnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestUnknownMessage
        extends ChannelRequestMessage<ChannelRequestUnknownMessage> {

    private ModifiableByteArray typeSpecificData;

    public ModifiableByteArray getTypeSpecificData() {
        return typeSpecificData;
    }

    public void setPassword(ModifiableByteArray typeSpecificData) {
        this.typeSpecificData = typeSpecificData;
    }

    public void setTypeSpecificData(byte[] typeSpecificData) {
        this.typeSpecificData =
                ModifiableVariableFactory.safelySetValue(this.typeSpecificData, typeSpecificData);
    }

    @Override
    public ChannelRequestUnknownMessageHandler getHandler(SshContext context) {
        return new ChannelRequestUnknownMessageHandler(context, this);
    }
}
