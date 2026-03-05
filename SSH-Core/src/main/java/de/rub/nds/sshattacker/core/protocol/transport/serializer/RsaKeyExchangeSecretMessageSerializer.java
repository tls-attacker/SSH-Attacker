/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeSecretMessageSerializer
        extends SshMessageSerializer<RsaKeyExchangeSecretMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeEncryptedSecret(
            RsaKeyExchangeSecretMessage object, SerializerStream output) {
        Integer encryptedSecretLength = object.getEncryptedSecretLength().getValue();
        LOGGER.debug("Encrypted secret length: {}", encryptedSecretLength);
        output.appendInt(encryptedSecretLength);
        byte[] encryptedSecret = object.getEncryptedSecret().getValue();
        LOGGER.debug(
                "Encrypted secret: {}", () -> ArrayConverter.bytesToRawHexString(encryptedSecret));
        output.appendBytes(encryptedSecret);
    }

    @Override
    protected void serializeMessageSpecificContents(
            RsaKeyExchangeSecretMessage object, SerializerStream output) {
        serializeEncryptedSecret(object, output);
    }
}
