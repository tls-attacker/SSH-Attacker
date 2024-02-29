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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.PortOpenMessageSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PortOpenMessageSSHV1Serializier extends SshMessageSerializer<PortOpenMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PortOpenMessageSSHV1Serializier(PortOpenMessageSSH1 message) {
        super(message);
    }

    private void serializeExitStatus() {
        LOGGER.warn(
                "Opening Port {} to {} on Channel {} with originator_string{}",
                message.getPort().getValue(),
                message.getHostName().getValue(),
                message.getLocalChannel().getValue(),
                message.getOriginatorString());
        appendInt(message.getLocalChannel().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getHostName().getValue().length(), DataFormatConstants.UINT32_SIZE);
        appendString(message.getHostName().getValue(), StandardCharsets.UTF_8);
        appendInt(message.getPort().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(
                message.getOriginatorString().getValue().length(), DataFormatConstants.UINT32_SIZE);
        appendString(message.getOriginatorString().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExitStatus();
    }
}
