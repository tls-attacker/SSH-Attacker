/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class GlobalRequestMessagePreparator<T extends GlobalRequestMessage<T>>
        extends SshMessagePreparator<T> {

    private final String globalRequestType;
    private final boolean wantReply;

    protected GlobalRequestMessagePreparator(
            Chooser chooser, T message, GlobalRequestType globalRequestType, boolean wantReply) {
        this(chooser, message, globalRequestType.toString(), wantReply);
    }

    protected GlobalRequestMessagePreparator(
            Chooser chooser, T message, String globalRequestType, boolean wantReply) {
        super(chooser, message, MessageIdConstant.SSH_MSG_GLOBAL_REQUEST);
        this.globalRequestType = globalRequestType;
        this.wantReply = wantReply;
    }

    @Override
    public final void prepareMessageSpecificContents() {
        getObject().setRequestName(globalRequestType, true);
        getObject().setWantReply(wantReply);
        prepareGlobalRequestMessageSpecificContents();
    }

    protected abstract void prepareGlobalRequestMessageSpecificContents();
}
