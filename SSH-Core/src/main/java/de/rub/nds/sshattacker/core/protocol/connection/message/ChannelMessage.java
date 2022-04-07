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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import javax.xml.bind.annotation.XmlAttribute;

public abstract class ChannelMessage<T extends ChannelMessage<T>> extends SshMessage<T> {

    protected ModifiableInteger recipientChannel;

    @XmlAttribute(name = "channel")
    protected Integer senderChannel;

    protected ChannelMessage() {}

    protected ChannelMessage(Integer senderChannel) {
        super();
        this.setSenderChannel(senderChannel);
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

    public Integer getSenderChannel() {
        return senderChannel;
    }

    public void setSenderChannel(int senderChannel) {
        this.senderChannel = senderChannel;
    }
}
