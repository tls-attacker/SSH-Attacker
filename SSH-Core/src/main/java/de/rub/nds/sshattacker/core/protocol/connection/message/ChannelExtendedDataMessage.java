/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelExtendedDataMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelExtendedDataMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelExtendedDataMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelExtendedDataMessage extends Message<ChannelExtendedDataMessage> {

    private ModifiableInteger recipientChannel;
    private ModifiableInteger dataTypeCode;
    private ModifiableByteArray data;

    public ModifiableInteger getRecipientChannel() {
        return recipientChannel;
    }

    public void setRecipientChannel(ModifiableInteger recipientChannel) {
        this.recipientChannel = recipientChannel;
    }

    public void setRecipientChannel(int recipientChannel) {
        this.recipientChannel = ModifiableVariableFactory.safelySetValue(this.recipientChannel, recipientChannel);
    }

    public ModifiableInteger getDataTypeCode() {
        return dataTypeCode;
    }

    public void setDataTypeCode(ModifiableInteger dataTypeCode) {
        this.dataTypeCode = dataTypeCode;
    }

    public void setDataTypeCode(int dataTypeCode) {
        this.dataTypeCode = ModifiableVariableFactory.safelySetValue(this.dataTypeCode, dataTypeCode);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public ChannelExtendedDataMessageHandler getHandler(SshContext context) {
        return new ChannelExtendedDataMessageHandler(context);
    }

    @Override
    public ChannelExtendedDataMessageSerializer getSerializer() {
        return new ChannelExtendedDataMessageSerializer(this);
    }

    @Override
    public ChannelExtendedDataMessagePreparator getPreparator(SshContext context) {
        return new ChannelExtendedDataMessagePreparator(context, this);
    }

}
