/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestXonXoffMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestXonXoffMessage
        extends ChannelRequestMessage<ChannelRequestXonXoffMessage> {

    private ModifiableByte clientFlowControl;
    private Byte transferClientFlowControl;

    public ChannelRequestXonXoffMessage() {
        super(ChannelRequestType.XON_XOFF);
    }

    public ChannelRequestXonXoffMessage(Integer senderChannel) {
        super(ChannelRequestType.XON_XOFF, senderChannel);
    }

    public ChannelRequestXonXoffMessage(Integer senderChannel, byte transferClientFlowControl) {
        super(ChannelRequestType.XON_XOFF, senderChannel);
        setTransferClientFlowControl(transferClientFlowControl);
    }

    public ModifiableByte getClientFlowControl() {
        return clientFlowControl;
    }

    public void setClientFlowControl(ModifiableByte clientFlowControl) {
        this.clientFlowControl = clientFlowControl;
    }

    public void setClientFlowControl(byte clientFlowControl) {
        this.clientFlowControl =
                ModifiableVariableFactory.safelySetValue(this.clientFlowControl, clientFlowControl);
    }

    public void setClientFlowControl(boolean clientFlowControl) {
        setClientFlowControl(Converter.booleanToByte(clientFlowControl));
    }

    public Byte getTransferClientFlowControl() {
        return transferClientFlowControl;
    }

    public void setTransferClientFlowControl(byte transferClientFlowControl) {
        this.transferClientFlowControl = transferClientFlowControl;
    }

    public void setTransferClientFlowControl(boolean transferClientFlowControl) {
        setTransferClientFlowControl(Converter.booleanToByte(transferClientFlowControl));
    }

    @Override
    public ChannelRequestXonXoffMessageHandler getHandler(SshContext context) {
        return new ChannelRequestXonXoffMessageHandler(context, this);
    }
}
