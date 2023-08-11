/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenConfirmationMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenConfirmationMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenConfirmationMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenConfirmationMessageSerializer;
import java.io.InputStream;

public class ChannelOpenConfirmationMessage extends ChannelMessage<ChannelOpenConfirmationMessage> {

    private ModifiableInteger senderChannelId;
    private ModifiableInteger windowSize;
    private ModifiableInteger packetSize;

    public ModifiableInteger getSenderChannelId() {
        return senderChannelId;
    }

    public void setSenderChannelId(ModifiableInteger senderChannelId) {
        this.senderChannelId = senderChannelId;
    }

    public void setSenderChannelId(int modSenderChannel) {
        this.senderChannelId =
                ModifiableVariableFactory.safelySetValue(this.senderChannelId, modSenderChannel);
    }

    public ModifiableInteger getWindowSize() {
        return windowSize;
    }

    public void setWindowSize(ModifiableInteger windowSize) {
        this.windowSize = windowSize;
    }

    public void setWindowSize(int windowSize) {
        this.windowSize = ModifiableVariableFactory.safelySetValue(this.windowSize, windowSize);
    }

    public ModifiableInteger getPacketSize() {
        return packetSize;
    }

    public void setPacketSize(ModifiableInteger packetSize) {
        this.packetSize = packetSize;
    }

    public void setPacketSize(int packetSize) {
        this.packetSize = ModifiableVariableFactory.safelySetValue(this.packetSize, packetSize);
    }

    @Override
    public ChannelOpenConfirmationMessageHandler getHandler(SshContext context) {
        return new ChannelOpenConfirmationMessageHandler(context);
    }

    @Override
    public ChannelOpenConfirmationMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelOpenConfirmationMessageParser(stream);
    }

    @Override
    public ChannelOpenConfirmationMessagePreparator getPreparator(SshContext context) {
        return new ChannelOpenConfirmationMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelOpenConfirmationMessageSerializer getSerializer(SshContext context) {
        return new ChannelOpenConfirmationMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "CHANNEL_OPEN_CONFIRMATION";
    }
}
