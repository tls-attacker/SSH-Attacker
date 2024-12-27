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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.PingMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class PingMessage extends SshMessage<PingMessage> {

    private ModifiableInteger dataLength;
    private ModifiableByteArray data;

    public PingMessage() {
        super();
    }

    public PingMessage(PingMessage other) {
        super(other);
        dataLength = other.dataLength != null ? other.dataLength.createCopy() : null;
        data = other.data != null ? other.data.createCopy() : null;
    }

    @Override
    public PingMessage createCopy() {
        return new PingMessage(this);
    }

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
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
        if (adjustLengthField) {
            setDataLength(this.data.getValue().length);
        }
    }

    public void setSoftlyData(byte[] data, boolean adjustLengthField, Config config) {
        if (this.data == null || this.data.getOriginalValue() == null) {
            this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || dataLength == null
                    || dataLength.getOriginalValue() == null) {
                setDataLength(this.data.getValue().length);
            }
        }
    }

    @Override
    public PingMessageHandler getHandler(SshContext context) {
        return new PingMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        PingMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return PingMessageHandler.SERIALIZER.serialize(this);
    }
}
