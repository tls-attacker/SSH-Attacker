/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DisconnectMessagePreparator extends SshMessagePreparator<DisconnectMessage> {

    public DisconnectMessagePreparator(Chooser chooser, DisconnectMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_DISCONNECT);
    }

    @Override
    public void prepareMessageSpecificContents() {

        if (chooser.getContext().getDelayCompressionExtensionNegotiationFailed()) {
            object.setSoftlyReasonCode(DisconnectReason.SSH_DISCONNECT_COMPRESSION_ERROR);
            object.setSoftlyDescription(
                    "No common compression algorithm found in delay-compression extension!",
                    true,
                    config);
            object.setSoftlyLanguageTag("", true, config);
        } else {
            // TODO save values in config
            object.setSoftlyReasonCode(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR);
            object.setSoftlyDescription("Test", true, config);
            object.setSoftlyLanguageTag("", true, config);
        }
    }
}
