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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenUnknownMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenUnknownMessageSerializer;
import java.io.InputStream;

public class ChannelOpenUnknownMessage extends ChannelOpenMessage<ChannelOpenUnknownMessage> {

    private ModifiableByteArray typeSpecificData;

    public ModifiableByteArray getTypeSpecificData() {
        return typeSpecificData;
    }

    public void setTypeSpecificData(byte[] typeSpecificData) {
        this.typeSpecificData =
                ModifiableVariableFactory.safelySetValue(this.typeSpecificData, typeSpecificData);
    }

    public void setTypeSpecificData(ModifiableByteArray typeSpecificData) {
        this.typeSpecificData = typeSpecificData;
    }

    @Override
    public ChannelOpenUnknownMessageHandler getHandler(SshContext context) {
        return new ChannelOpenUnknownMessageHandler(context);
    }

    @Override
    public ChannelOpenUnknownMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelOpenUnknownMessageParser(stream);
    }

    @Override
    public ChannelOpenUnknownMessagePreparator getPreparator(SshContext context) {
        return new ChannelOpenUnknownMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelOpenUnknownMessageSerializer getSerializer(SshContext context) {
        return new ChannelOpenUnknownMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "UNKONW";
    }
}
