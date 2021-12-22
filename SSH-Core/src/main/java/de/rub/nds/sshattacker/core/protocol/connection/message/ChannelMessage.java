/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;

public abstract class ChannelMessage<T extends ChannelMessage<T>> extends SshMessage<T> {

    protected ModifiableInteger recipientChannel;

    protected ModifiableInteger senderChannel;

    protected ChannelMessage(MessageIDConstant messageID) {
        super(messageID);
    }

    public ModifiableInteger getRecipientChannel() {
        return recipientChannel;
    }

    public void setRecipientChannel(ModifiableInteger recipientChannel) {
        this.recipientChannel = recipientChannel;
    }

    public void setRecipientChannel(int recipientChannel) {
        this.recipientChannel =
                ModifiableVariableFactory.safelySetValue(this.recipientChannel, recipientChannel);
    }

    public ModifiableInteger getSenderChannel() {
        return senderChannel;
    }

    public void setSenderChannel(ModifiableInteger senderChannel) {
        this.senderChannel = senderChannel;
    }

    public void setSenderChannel(int senderChannel) {
        this.senderChannel =
                ModifiableVariableFactory.safelySetValue(this.senderChannel, senderChannel);
    }
}
