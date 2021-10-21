/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UnimplementedMessagePreparator extends SshMessagePreparator<UnimplementedMessage> {

    public UnimplementedMessagePreparator(SshContext context, UnimplementedMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_UNIMPLEMENTED);
        // TODO dummy values for fuzzing
        getObject().setSequenceNumber(Integer.MAX_VALUE);
    }
}
