/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.protocol.handler.ChannelExtendedDataMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelExtendedDataMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelExtendedDataMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelExtendedDataMessage extends Message<ChannelExtendedDataMessage> {

    private ModifiableInteger recipientChannel;
    private ModifiableInteger dataTypeCode;
    private ModifiableString data;

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

    public ModifiableString getData() {
        return data;
    }

    public void setData(ModifiableString data) {
        this.data = data;
    }

    public void setData(String data) {
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
