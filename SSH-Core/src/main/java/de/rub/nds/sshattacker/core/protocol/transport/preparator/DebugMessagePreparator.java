/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DebugMessagePreparator extends Preparator<DebugMessage> {

    public DebugMessagePreparator(SshContext context, DebugMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_DEBUG.id);

        // TODO dummy values for fuzzing
        message.setMessage("");
        message.setLanguageTag("");
        message.setAlwaysDisplay(true);
    }

}
