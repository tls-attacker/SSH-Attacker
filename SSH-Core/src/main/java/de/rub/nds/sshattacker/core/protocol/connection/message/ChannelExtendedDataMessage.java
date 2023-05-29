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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelExtendedDataMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelExtendedDataMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelExtendedDataMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelExtendedDataMessageSerializer;
import java.io.InputStream;

public class ChannelExtendedDataMessage extends ChannelMessage<ChannelExtendedDataMessage> {

    private ModifiableInteger dataTypeCode;
    private ModifiableInteger dataLength;
    private ModifiableByteArray data;

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

    @Override
    public ChannelExtendedDataMessageHandler getHandler(SshContext context) {
        return new ChannelExtendedDataMessageHandler(context);
    }

    /*
        @Override
        public ChannelExtendedDataMessageParser getParser(byte[] array) {
            return new ChannelExtendedDataMessageParser(array);
        }
    */

    @Override
    public ChannelExtendedDataMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelExtendedDataMessageParser(stream);
    }

    @Override
    public ChannelExtendedDataMessagePreparator getPreparator(SshContext context) {
        return new ChannelExtendedDataMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelExtendedDataMessageSerializer getSerializer(SshContext context) {
        return new ChannelExtendedDataMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "CHANEXTEND";
    }
}
