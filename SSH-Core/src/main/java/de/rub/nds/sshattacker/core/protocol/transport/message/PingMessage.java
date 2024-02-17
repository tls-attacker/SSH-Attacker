/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.PingMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.PingMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.PingMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.PingMessageSerializer;
import java.io.InputStream;

public class PingMessage extends SshMessage<PingMessage> {

    private ModifiableInteger dataLength;
    private ModifiableByteArray data;

    public ModifiableInteger getDataLength() {
        return dataLength;
    }

    public void setDataLength(ModifiableInteger dataLength) {
        this.dataLength = dataLength;
    }

    public void setDataLength(int dataLength) {
        this.dataLength = ModifiableVariableFactory.safelySetValue(this.dataLength, dataLength);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        setData(data, false);
    }

    public void setData(ModifiableByteArray data, boolean adjustLengthField) {
        if (adjustLengthField) {
            setDataLength(data.getValue().length);
        }
        this.data = data;
    }

    public void setData(byte[] data) {
        setData(data, false);
    }

    public void setData(byte[] data, boolean adjustLengthField) {
        if (adjustLengthField) {
            setDataLength(data.length);
        }
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public PingMessageHandler getHandler(SshContext context) {
        return new PingMessageHandler(context);
    }

    @Override
    public PingMessageParser getParser(SshContext context, InputStream stream) {
        return new PingMessageParser(stream);
    }

    @Override
    public PingMessagePreparator getPreparator(SshContext context) {
        return new PingMessagePreparator(context.getChooser(), this);
    }

    @Override
    public PingMessageSerializer getSerializer(SshContext context) {
        return new PingMessageSerializer(this);
    }
}
