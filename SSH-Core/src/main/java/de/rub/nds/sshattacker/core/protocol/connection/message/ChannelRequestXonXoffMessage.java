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

public class ChannelRequestXonXoffMessage
        extends ChannelRequestMessage<ChannelRequestXonXoffMessage> {

    private ModifiableByte clientFlowControl;

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

    @Override
    public ChannelRequestXonXoffMessageHandler getHandler(SshContext context) {
        return new ChannelRequestXonXoffMessageHandler(context, this);
    }
}
