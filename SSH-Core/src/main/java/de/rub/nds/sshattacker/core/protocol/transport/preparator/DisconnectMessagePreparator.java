/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DisconnectMessagePreparator extends SshMessagePreparator<DisconnectMessage> {

    public DisconnectMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_DISCONNECT);
    }

    @Override
    public void prepareMessageSpecificContents(DisconnectMessage object, Chooser chooser) {

        if (chooser.getContext().getDelayCompressionExtensionNegotiationFailed()) {
            object.setReasonCode(DisconnectReason.SSH_DISCONNECT_COMPRESSION_ERROR);
            object.setDescription(
                    "No common compression algorithm found in delay-compression extension!", true);
            object.setLanguageTag("", true);
        } else {
            // TODO save values in chooser.getConfig()
            object.setReasonCode(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR);
            object.setDescription("Test", true);
            object.setLanguageTag("", true);
        }
    }
}
