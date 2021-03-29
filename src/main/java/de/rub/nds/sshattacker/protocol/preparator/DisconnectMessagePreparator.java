/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.DisconnectMessage;
import de.rub.nds.sshattacker.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessagePreparator extends Preparator<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessagePreparator(SshContext context, DisconnectMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        // TODO save values in config
        message.setMessageID(MessageIDConstant.SSH_MSG_DISCONNECT.id);
        message.setReasonCode(0);
        message.setLanguageTag("");
        message.setDescription("Test");
    }

}
