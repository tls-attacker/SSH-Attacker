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
import de.rub.nds.sshattacker.core.protocol.message.IgnoreMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class IgnoreMessagePreparator extends Preparator<IgnoreMessage> {

    public IgnoreMessagePreparator(SshContext context, IgnoreMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_IGNORE.id);

        // TODO dummy values for fuzzing
        message.setData("");
    }

}
