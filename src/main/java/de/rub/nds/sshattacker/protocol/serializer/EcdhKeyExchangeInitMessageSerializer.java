/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageSerializer extends MessageSerializer<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final EcdhKeyExchangeInitMessage msg;

    public EcdhKeyExchangeInitMessageSerializer(EcdhKeyExchangeInitMessage msg) {
        super(msg);
        this.msg = msg;
    }

    private void serializePublicKeyLength() {
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
        appendInt(msg.getPublicKeyLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializePublicKey() {
        LOGGER.debug("PublicKey: " + msg.getPublicKey());
        appendBytes(msg.getPublicKey().getValue());
    }

    @Override
    public byte[] serializeMessageSpecificPayload() {
        serializePublicKeyLength();
        serializePublicKey();
        return getAlreadySerialized();
    }
}
