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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.PortForwardRequestMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.X11OpenMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class PortForwardRequestMessageSSHV1Serializier extends SshMessageSerializer<PortForwardRequestMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PortForwardRequestMessageSSHV1Serializier(PortForwardRequestMessageSSH1 message) {
        super(message);
    }

    private void serializeExitStatus() {
        LOGGER.debug("Forwarding {} to {}:{}", message.getServerPort().getValue(),message.getHostToConnect().getValue(),message.getPortToConnect().getValue());
        appendInt(message.getServerPort().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getHostToConnect().getValue().length(), DataFormatConstants.UINT32_SIZE);
        appendString(message.getHostToConnect().getValue(), StandardCharsets.UTF_8);
        appendInt(message.getPortToConnect().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExitStatus();
    }
}
