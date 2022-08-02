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
import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelExtendedDataMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelExtendedDataMessage extends ChannelMessage<ChannelExtendedDataMessage> {

    private ModifiableInteger dataTypeCode;
    private ModifiableInteger dataLength;
    private ModifiableByteArray data;

    public ChannelExtendedDataMessage() {
        super(MessageIdConstant.SSH_MSG_CHANNEL_EXTENDED_DATA);
    }

    public ChannelExtendedDataMessage(Integer senderChannel) {
        this();
        this.setSenderChannel(senderChannel);
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
        if (adjustLengthField) {
            setDataLength(data.getValue().length);
        }
        this.data = data;
    }

    public void setData(byte[] data, boolean adjustLengthField) {
        if (adjustLengthField) {
            setDataLength(data.length);
        }
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public ChannelExtendedDataMessageHandler getHandler(SshContext context) {
        return new ChannelExtendedDataMessageHandler(context, this);
    }
}
