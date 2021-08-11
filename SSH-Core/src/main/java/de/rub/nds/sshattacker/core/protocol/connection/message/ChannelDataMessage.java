/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelDataMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelDataMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelDataMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelDataMessage extends ChannelMessage<ChannelDataMessage> {

    private ModifiableInteger dataLength;
    private ModifiableByteArray data;

    public ChannelDataMessage() {
        super(MessageIDConstant.SSH_MSG_CHANNEL_DATA);
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
    public ChannelDataMessageHandler getHandler(SshContext context) {
        return new ChannelDataMessageHandler(context);
    }

    @Override
    public ChannelDataMessageSerializer getSerializer() {
        return new ChannelDataMessageSerializer(this);
    }

    @Override
    public ChannelDataMessagePreparator getPreparator(SshContext context) {
        return new ChannelDataMessagePreparator(context, this);
    }
}
