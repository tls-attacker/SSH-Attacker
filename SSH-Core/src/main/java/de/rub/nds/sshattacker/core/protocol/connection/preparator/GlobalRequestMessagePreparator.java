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
            GlobalRequestType globalRequestType, boolean wantReply) {
        this(globalRequestType.toString(), wantReply);
    }

    protected GlobalRequestMessagePreparator(String globalRequestType, boolean wantReply) {
        super(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST);
        this.globalRequestType = globalRequestType;
        this.wantReply = wantReply;
    }

    @Override
    protected void prepareMessageSpecificContents(T object, Chooser chooser) {
        // Always set correct request name -> Don't use soft set
        object.setRequestName(globalRequestType, true);
        object.setWantReply(wantReply);
        prepareGlobalRequestMessageSpecificContents(object, chooser);
    }

    protected abstract void prepareGlobalRequestMessageSpecificContents(T object, Chooser chooser);
}
