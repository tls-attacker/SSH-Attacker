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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SshMessagePreparator<T extends SshMessage<T>>
        extends ProtocolMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ModifiableByte messageId;

    public SshMessagePreparator(Chooser chooser, T message, MessageIdConstant messageId) {
        super(chooser, message);
        this.messageId = ModifiableVariableFactory.safelySetValue(null, messageId.getId());
    }

    public SshMessagePreparator(Chooser chooser, T message, MessageIdConstantSSH1 messageId) {
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
