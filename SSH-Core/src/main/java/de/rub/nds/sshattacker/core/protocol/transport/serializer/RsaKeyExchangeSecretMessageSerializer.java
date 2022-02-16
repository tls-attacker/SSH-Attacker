/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeSecretMessageSerializer
        extends SshMessageSerializer<RsaKeyExchangeSecretMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeSecretMessageSerializer(RsaKeyExchangeSecretMessage message) {
        super(message);
    }

    private void serializeEncryptedSecret() {
        LOGGER.debug("Encrypted secret length: " + message.getEncryptedSecretLength().getValue());
        appendInt(
                message.getEncryptedSecretLength().getValue(),
                DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug(
                "Encrypted secret: " + Arrays.toString(message.getEncryptedSecret().getValue()));
        appendBytes(message.getEncryptedSecret().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeEncryptedSecret();
    }
}
