/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.NoMoreSessionsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class NoMoreSessionsMessagePreparator extends SshMessagePreparator<NoMoreSessionsMessage> {

    public NoMoreSessionsMessagePreparator(Chooser chooser, NoMoreSessionsMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_GLOBAL_REQUEST);
        getObject().setRequestName(GlobalRequestType.NO_MORE_SESSIONS_OPENSSH_COM);
        getObject().setWantReply(chooser.getConfig().getReplyWanted());
    }
}
