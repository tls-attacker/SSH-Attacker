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
import de.rub.nds.sshattacker.core.state.SshContext;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlType(namespace = "ssh-attacker")
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class SshMessage<T extends SshMessage<T>> extends ProtocolMessage<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ModifiableByte messageId;

    protected SshMessage(byte messageId) {
        this.setMessageId(messageId);
    }

    protected SshMessage(MessageIdConstant messageId) {
        this(messageId.getId());
    }

    public ModifiableByte getMessageId() {
        return messageId;
    }

    public void setMessageId(ModifiableByte messageId) {
        this.messageId = messageId;
    }

    public void setMessageId(byte messageId) {
        this.messageId = ModifiableVariableFactory.safelySetValue(this.messageId, messageId);
    }

    public void setMessageId(MessageIdConstant messageId) {
        setMessageId(messageId.getId());
    }

    @Override
    public abstract SshMessageHandler<T> getHandler(SshContext context);

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }
}
