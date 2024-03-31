/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ChannelDataMessageSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageSSHV1Serializier
        extends Ssh1MessageSerializer<ChannelDataMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageSSHV1Serializier(ChannelDataMessageSSH1 message) {
        super(message);
    }

    private void serializeExitStatus() {
        LOGGER.debug(
                "Failed Sending data on channel {} with data {}",
                message.getRemoteChannel().getValue(),
                message.getData().getValue());
        appendInt(message.getRemoteChannel().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getData().getValue().length(), DataFormatConstants.UINT32_SIZE);
        appendString(message.getData().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExitStatus();
    }
}
