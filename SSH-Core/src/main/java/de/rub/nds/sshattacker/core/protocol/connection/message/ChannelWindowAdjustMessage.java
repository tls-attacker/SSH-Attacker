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
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelWindowAdjustMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelWindowAdjustMessage extends ChannelMessage<ChannelWindowAdjustMessage> {

    private ModifiableInteger bytesToAdd;
    private Integer transferBytesToAdd;

    public ChannelWindowAdjustMessage() {
        super(MessageIdConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST);
    }

    public ChannelWindowAdjustMessage(Integer senderChannel) {
        super(MessageIdConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST, senderChannel);
    }

    public ChannelWindowAdjustMessage(Integer senderChannel, Integer bytesToAdd) {
        super(MessageIdConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST, senderChannel);
        setTransferBytesToAdd(bytesToAdd);
    }

    public ModifiableInteger getBytesToAdd() {
        return bytesToAdd;
    }

    public void setBytesToAdd(ModifiableInteger bytesToAdd) {
        this.bytesToAdd = bytesToAdd;
    }

    public void setBytesToAdd(int bytesToAdd) {
        this.bytesToAdd = ModifiableVariableFactory.safelySetValue(this.bytesToAdd, bytesToAdd);
    }

    public Integer getTransferBytesToAdd() {
        return transferBytesToAdd;
    }

    public void setTransferBytesToAdd(int transferBytesToAdd) {
        this.transferBytesToAdd = transferBytesToAdd;
    }

    @Override
    public ChannelWindowAdjustMessageHandler getHandler(SshContext context) {
        return new ChannelWindowAdjustMessageHandler(context, this);
    }
}
