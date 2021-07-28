/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageSerializer extends MessageSerializer<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeInitMessageSerializer(EcdhKeyExchangeInitMessage msg) {
        super(msg);
    }

    private void serializePublicKey() {
        LOGGER.debug("Public key length: " + msg.getPublicKeyLength().getValue());
        appendInt(msg.getPublicKeyLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Public key: " + ArrayConverter.bytesToRawHexString(msg.getPublicKey().getValue()));
        appendBytes(msg.getPublicKey().getValue());
    }

    @Override
    public void serializeMessageSpecificPayload() {
        serializePublicKey();
    }
}
