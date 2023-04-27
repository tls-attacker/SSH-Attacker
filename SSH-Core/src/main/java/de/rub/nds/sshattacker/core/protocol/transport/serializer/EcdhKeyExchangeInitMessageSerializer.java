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
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageSerializer
        extends SshMessageSerializer<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeInitMessageSerializer(EcdhKeyExchangeInitMessage message) {
        super(message);
    }

    private void serializeEphemeralPublicKey() {
        LOGGER.debug(
                "Ephemeral public key (client) length: "
                        + message.getEphemeralPublicKeyLength().getValue());
        appendInt(
                message.getEphemeralPublicKeyLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Ephemeral public key (client): "
                        + ArrayConverter.bytesToRawHexString(
                                message.getEphemeralPublicKey().getValue()));
        appendBytes(message.getEphemeralPublicKey().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeEphemeralPublicKey();
    }
}
