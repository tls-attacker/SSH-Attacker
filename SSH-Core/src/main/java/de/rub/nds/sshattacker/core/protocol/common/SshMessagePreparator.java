/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SshMessagePreparator<T extends SshMessage<T>>
        extends ProtocolMessagePreparator<T> {

    private final MessageIdConstant messageId;

    protected SshMessagePreparator(MessageIdConstant messageId) {
        super();
        this.messageId = messageId;
    }

    @Override
    protected final void prepareProtocolMessageContents(T object, Chooser chooser) {
        // Always set correct message id -> Don't use soft set
        object.setMessageId(messageId);
        prepareMessageSpecificContents(object, chooser);
    }

    public abstract void prepareMessageSpecificContents(T object, Chooser chooser);
}
