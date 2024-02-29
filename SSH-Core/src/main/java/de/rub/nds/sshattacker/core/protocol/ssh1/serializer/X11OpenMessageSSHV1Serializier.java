/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ChannelDataMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.X11OpenMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class X11OpenMessageSSHV1Serializier extends SshMessageSerializer<X11OpenMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X11OpenMessageSSHV1Serializier(X11OpenMessageSSH1 message) {
        super(message);
    }

    private void serializeExitStatus() {
        LOGGER.debug("Failed Sending data on channel {} with data {}", message.getLocalChannel().getValue(),message.getOriginatorString().getValue());
        appendInt(message.getLocalChannel().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getOriginatorString().getValue().length(), DataFormatConstants.UINT32_SIZE);
        appendString(message.getOriginatorString().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExitStatus();
    }
}
