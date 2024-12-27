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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestXonXoffMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestXonXoffMessage
        extends ChannelRequestMessage<ChannelRequestXonXoffMessage> {

    private ModifiableByte clientFlowControl;

    public ChannelRequestXonXoffMessage() {
        super();
    }

    public ChannelRequestXonXoffMessage(ChannelRequestXonXoffMessage other) {
        super(other);
        clientFlowControl =
                other.clientFlowControl != null ? other.clientFlowControl.createCopy() : null;
    }

    @Override
    public ChannelRequestXonXoffMessage createCopy() {
        return new ChannelRequestXonXoffMessage(this);
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

    public void setSoftlyClientFlowControl(byte clientFlowControl) {
        if (this.clientFlowControl == null || this.clientFlowControl.getOriginalValue() == null) {
            this.clientFlowControl =
                    ModifiableVariableFactory.safelySetValue(
                            this.clientFlowControl, clientFlowControl);
        }
    }

    public void setClientFlowControl(boolean clientFlowControl) {
        setClientFlowControl(Converter.booleanToByte(clientFlowControl));
    }

    @Override
    public ChannelRequestXonXoffMessageHandler getHandler(SshContext context) {
        return new ChannelRequestXonXoffMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelRequestXonXoffMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestXonXoffMessageHandler.SERIALIZER.serialize(this);
    }
}
