/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer;

import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.layer.context.LayerContext;
import de.rub.nds.sshattacker.core.layer.data.DataContainer;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlSeeAlso;

/**
 * Abstract class for different messages the SSH-Attacker can send. This includes but is not limited
 * to SSH-Messages.
 *
 * @param <Self> The message class itself
 * @param <Context> The type of context this message needs to use, relates to the messages' layer.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({Message.class, ProtocolMessage.class})
public abstract class Message<Self extends Message<?, ?>, Context extends LayerContext>
        extends ModifiableVariableHolder implements DataContainer<Self, Context> {

    public abstract String toShortString();
}
