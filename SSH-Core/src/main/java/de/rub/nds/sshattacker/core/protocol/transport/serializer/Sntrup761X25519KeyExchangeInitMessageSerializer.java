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
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup761X25519KeyExchangeInitMessageSerializer
        extends SshMessageSerializer<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public Sntrup761X25519KeyExchangeInitMessageSerializer(
            HybridKeyExchangeInitMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {
        int length =
                message.getEphemeralECPublicKeyLength().getValue()
                        + message.getEphemeralSNTRUPPublicKeyLength().getValue();
        byte[] keys =
                ArrayConverter.concatenate(
                        message.getEphemeralSNTRUPPublicKey().getValue(),
                        message.getEphemeralECPublicKey().getValue());

        LOGGER.debug("x25519 || sntrup761 public Key (client) length: " + length);
        appendInt(length, DataFormatConstants.STRING_SIZE_LENGTH);

        LOGGER.debug(
                "x25519 || sntrup761 public Key (client): "
                        + ArrayConverter.bytesToHexString(keys));
        appendBytes(keys);
    }
}
