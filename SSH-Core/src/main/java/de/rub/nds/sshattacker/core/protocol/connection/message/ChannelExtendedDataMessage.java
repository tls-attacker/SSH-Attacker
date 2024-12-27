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
import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelExtendedDataMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelExtendedDataMessage extends ChannelMessage<ChannelExtendedDataMessage> {

    private ModifiableInteger dataTypeCode;
    private ModifiableInteger dataLength;
    private ModifiableByteArray data;

    public ChannelExtendedDataMessage() {
        super();
    }

    public ChannelExtendedDataMessage(ChannelExtendedDataMessage other) {
        super(other);
        dataTypeCode = other.dataTypeCode != null ? other.dataTypeCode.createCopy() : null;
        dataLength = other.dataLength != null ? other.dataLength.createCopy() : null;
        data = other.data != null ? other.data.createCopy() : null;
    }

    @Override
    public ChannelExtendedDataMessage createCopy() {
        return new ChannelExtendedDataMessage(this);
    }

    public ModifiableInteger getDataTypeCode() {
        return dataTypeCode;
    }

    public void setDataTypeCode(ModifiableInteger dataTypeCode) {
        this.dataTypeCode = dataTypeCode;
    }

    public void setDataTypeCode(int dataTypeCode) {
        this.dataTypeCode =
                ModifiableVariableFactory.safelySetValue(this.dataTypeCode, dataTypeCode);
    }

    public void setSoftlyDataTypeCode(int dataTypeCode) {
        if (this.dataTypeCode == null || this.dataTypeCode.getOriginalValue() == null) {
            this.dataTypeCode =
                    ModifiableVariableFactory.safelySetValue(this.dataTypeCode, dataTypeCode);
        }
    }

    public void setDataTypeCode(ExtendedChannelDataType dataType) {
        setDataTypeCode(dataType.getDataTypeCode());
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
    public ChannelExtendedDataMessageHandler getHandler(SshContext context) {
        return new ChannelExtendedDataMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelExtendedDataMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelExtendedDataMessageHandler.SERIALIZER.serialize(this);
    }
}
