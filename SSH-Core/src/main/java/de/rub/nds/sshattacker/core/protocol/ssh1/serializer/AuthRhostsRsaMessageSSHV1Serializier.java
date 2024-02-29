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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AuthRhostsRsaMessageSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthRhostsRsaMessageSSHV1Serializier
        extends SshMessageSerializer<AuthRhostsRsaMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AuthRhostsRsaMessageSSHV1Serializier(AuthRhostsRsaMessageSSH1 message) {
        super(message);
    }

    private void serializeExitStatus() {
        appendInt(message.getUsername().getValue().length(), DataFormatConstants.UINT32_SIZE);
        appendString(message.getUsername().getValue(), StandardCharsets.UTF_8);
        appendInt(message.getClientHostKeyBits().getValue(), DataFormatConstants.UINT32_SIZE);
        appendMultiPrecisionAsByteArray(message.getHostPublicExponent().getValue());
        appendMultiPrecisionAsByteArray(message.getHostPublicModulus().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExitStatus();
    }
}
