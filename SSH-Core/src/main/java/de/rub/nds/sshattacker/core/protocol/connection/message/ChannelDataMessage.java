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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelDataMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelDataMessage extends ChannelMessage<ChannelDataMessage> {

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

    public void setData(byte[] data) {
        setData(data, false);
    }

    public void setData(ModifiableByteArray data, boolean adjustLengthField) {
        this.data = data;
        if (adjustLengthField) {
            setDataLength(this.data.getValue().length);
        }
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
    public ChannelDataMessageHandler getHandler(SshContext context) {
        return new ChannelDataMessageHandler(context, this);
    }
}
