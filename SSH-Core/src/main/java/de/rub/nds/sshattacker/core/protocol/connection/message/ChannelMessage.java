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
import jakarta.xml.bind.annotation.XmlAttribute;

public abstract class ChannelMessage<T extends ChannelMessage<T>> extends SshMessage<T> {

    protected ModifiableInteger recipientChannelId;

    @XmlAttribute(name = "localChannel")
    protected Integer configLocalChannelId;

    @XmlAttribute(name = "remoteChannel")
    protected Integer configRemoteChannelId;

    protected ChannelMessage() {
        super();
    }

    protected ChannelMessage(ChannelMessage<T> other) {
        super(other);
        recipientChannelId =
                other.recipientChannelId != null ? other.recipientChannelId.createCopy() : null;
        configLocalChannelId = other.configLocalChannelId;
        configRemoteChannelId = other.configRemoteChannelId;
    }

    @Override
    public abstract ChannelMessage<T> createCopy();

    public ModifiableInteger getRecipientChannelId() {
        return recipientChannelId;
    }

    public void setRecipientChannelId(ModifiableInteger recipientChannelId) {
        this.recipientChannelId = recipientChannelId;
    }

    public void setRecipientChannelId(int recipientChannel) {
        recipientChannelId =
                ModifiableVariableFactory.safelySetValue(recipientChannelId, recipientChannel);
    }

    public Integer getConfigLocalChannelId() {
        return configLocalChannelId;
    }

    public void setConfigLocalChannelId(int configLocalChannelId) {
        this.configLocalChannelId = configLocalChannelId;
    }

    public Integer getConfigRemoteChannelId() {
        return configRemoteChannelId;
    }

    public void setConfigRemoteChannelId(int configRemoteChannelId) {
        this.configRemoteChannelId = configRemoteChannelId;
    }
}
