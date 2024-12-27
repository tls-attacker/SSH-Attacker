/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import jakarta.xml.bind.annotation.XmlType;

@XmlType(namespace = "ssh-attacker")
public abstract class SshMessage<T extends SshMessage<T>> extends ProtocolMessage<T> {

    protected ModifiableByte messageId;

    protected SshMessage() {
        super();
    }

    protected SshMessage(SshMessage<T> other) {
        super(other);
        messageId = other.messageId != null ? other.messageId.createCopy() : null;
    }

    @Override
    public abstract SshMessage<T> createCopy();

    public ModifiableByte getMessageId() {
        return messageId;
    }

    public void setMessageId(ModifiableByte messageId) {
        this.messageId = messageId;
    }

    public void setMessageId(byte messageId) {
        this.messageId = ModifiableVariableFactory.safelySetValue(this.messageId, messageId);
    }

    public void setSoftlyMessageId(byte messageId) {
        if (this.messageId == null || this.messageId.getOriginalValue() == null) {
            this.messageId = ModifiableVariableFactory.safelySetValue(this.messageId, messageId);
        }
    }

    public void setMessageId(MessageIdConstant messageId) {
        setMessageId(messageId.getId());
    }

    public void setSoftlyMessageId(MessageIdConstant messageId) {
        setSoftlyMessageId(messageId.getId());
    }

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }
}
