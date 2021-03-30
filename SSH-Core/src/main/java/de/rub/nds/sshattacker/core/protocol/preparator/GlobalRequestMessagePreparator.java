/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestMessagePreparator extends Preparator<GlobalRequestMessage> {

    public GlobalRequestMessagePreparator(SshContext context, GlobalRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_GLOBAL_REQUEST.id);

        // TODO dummy values for fuzzing
        message.setWantReply((byte) 0xff);
        message.setRequestName("");
        message.setPayload(new byte[0]);
    }

}
