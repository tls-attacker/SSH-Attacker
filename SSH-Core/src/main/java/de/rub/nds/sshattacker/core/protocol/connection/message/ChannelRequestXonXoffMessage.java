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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestXonXoffMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestXonXoffMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestXonXoffMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestXonXoffMessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import java.io.InputStream;

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
        return new ChannelRequestXonXoffMessageHandler(context);
    }

    @Override
    public ChannelRequestXonXoffMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelRequestXonXoffMessageParser(stream);
    }

    @Override
    public ChannelRequestXonXoffMessagePreparator getPreparator(SshContext context) {
        return new ChannelRequestXonXoffMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelRequestXonXoffMessageSerializer getSerializer(SshContext context) {
        return new ChannelRequestXonXoffMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "REQ_XON_XOFF";
    }
}
