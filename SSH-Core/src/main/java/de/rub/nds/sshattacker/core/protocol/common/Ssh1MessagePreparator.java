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
import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class Ssh1MessagePreparator<T extends Ssh1Message<T>>
        extends ProtocolMessagePreparator<T> {

    private final ModifiableByte messageId;

    protected Ssh1MessagePreparator(Chooser chooser, T message, MessageIdConstant messageId) {
        super(chooser, message);
        this.messageId = ModifiableVariableFactory.safelySetValue(null, messageId.getId());
    }

    protected Ssh1MessagePreparator(Chooser chooser, T message, MessageIdConstantSSH1 messageId) {
        super(chooser, message);
        this.messageId = ModifiableVariableFactory.safelySetValue(null, messageId.getId());
    }

    @Override
    protected final void prepareProtocolMessageContents() {
        getObject().setMessageId(messageId);
        prepareMessageSpecificContents();
    }

    public abstract void prepareMessageSpecificContents();
}
