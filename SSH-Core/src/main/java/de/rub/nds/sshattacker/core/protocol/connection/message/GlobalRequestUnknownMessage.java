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
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestUnknownMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestUnknownMessageSerializer;
import java.io.InputStream;

public class GlobalRequestUnknownMessage extends GlobalRequestMessage<GlobalRequestUnknownMessage> {

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
    public GlobalRequestUnknownMessageHandler getHandler(SshContext context) {
        return new GlobalRequestUnknownMessageHandler(context);
    }

    @Override
    public GlobalRequestUnknownMessageParser getParser(SshContext context, InputStream stream) {
        return new GlobalRequestUnknownMessageParser(stream);
    }

    @Override
    public GlobalRequestUnknownMessagePreparator getPreparator(SshContext context) {
        return new GlobalRequestUnknownMessagePreparator(context.getChooser(), this);
    }

    @Override
    public GlobalRequestUnknownMessageSerializer getSerializer(SshContext context) {
        return new GlobalRequestUnknownMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "REQ_UNKONW";
    }
}
