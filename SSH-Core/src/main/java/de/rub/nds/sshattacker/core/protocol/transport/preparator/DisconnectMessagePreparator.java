/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DisconnectMessagePreparator extends SshMessagePreparator<DisconnectMessage> {

    public DisconnectMessagePreparator(SshContext context, DisconnectMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_DISCONNECT);
        // TODO save values in config
        getObject().setReasonCode(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR);
        getObject().setDescription("Test", true);
        getObject().setLanguageTag("", true);
    }
}
