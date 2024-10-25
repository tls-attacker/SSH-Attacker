/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.StderrDataMessageSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StderrDataMessageSSHV1Serializier
        extends Ssh1MessageSerializer<StderrDataMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StderrDataMessageSSHV1Serializier(StderrDataMessageSSH1 message) {
        super(message);
    }

    private void serializeReason() {
        LOGGER.debug("ErrorData length: {}", message.getErrorData().getValue());
        appendInt(
                message.getErrorData().getValue().length(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("ErrorData: {}", message.getErrorData().getValue());
        appendString(message.getErrorData().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeReason();
    }
}
