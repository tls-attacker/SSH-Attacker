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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestUnknownMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestUnknownMessageSerializer;
import java.io.InputStream;

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
        return new ChannelRequestUnknownMessageHandler(context);
    }

    @Override
    public ChannelRequestUnknownMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelRequestUnknownMessageParser(stream);
    }

    @Override
    public ChannelRequestUnknownMessagePreparator getPreparator(SshContext context) {
        return new ChannelRequestUnknownMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelRequestUnknownMessageSerializer getSerializer(SshContext context) {
        return new ChannelRequestUnknownMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "REQ_UNKONW_MESSAEG";
    }
}
