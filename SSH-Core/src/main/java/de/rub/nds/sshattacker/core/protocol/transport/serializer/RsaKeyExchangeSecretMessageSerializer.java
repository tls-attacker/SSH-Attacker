/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeSecretMessageSerializer
        extends SshMessageSerializer<RsaKeyExchangeSecretMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeSecretMessageSerializer(RsaKeyExchangeSecretMessage message) {
        super(message);
    }

    private void serializeEncryptedSecret() {
        Integer encryptedSecretLength = message.getEncryptedSecretLength().getValue();
        LOGGER.debug("Encrypted secret length: {}", encryptedSecretLength);
        appendInt(encryptedSecretLength, DataFormatConstants.MPINT_SIZE_LENGTH);
        byte[] encryptedSecret = message.getEncryptedSecret().getValue();
        LOGGER.debug(
                "Encrypted secret: {}", () -> ArrayConverter.bytesToRawHexString(encryptedSecret));
        appendBytes(encryptedSecret);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeEncryptedSecret();
    }
}
