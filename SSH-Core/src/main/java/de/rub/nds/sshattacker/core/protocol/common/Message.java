/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.state.SshContext;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlType(namespace = "ssh-attacker")
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Message<T extends Message<T>> extends ProtocolMessage {

    protected ModifiableByte messageID;

    protected Message() {
    }

    protected Message(MessageIDConstant messageID) {
        setMessageID(messageID);
    }

    public ModifiableByte getMessageID() {
        return messageID;
    }

    public void setMessageID(ModifiableByte messageID) {
        this.messageID = messageID;
    }

    public void setMessageID(byte messageID) {
        this.messageID = ModifiableVariableFactory.safelySetValue(this.messageID, messageID);
    }

    public void setMessageID(MessageIDConstant messageID) {
        setMessageID(messageID.id);
    }

    public abstract Handler<T> getHandler(SshContext context);

    @SuppressWarnings("unchecked")
    public void handleSelf(SshContext context) {
        getHandler(context).handle((T) this);
    }

    public abstract Serializer<T> getSerializer();

    public abstract Preparator<T> getPreparator(SshContext context);

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

}
