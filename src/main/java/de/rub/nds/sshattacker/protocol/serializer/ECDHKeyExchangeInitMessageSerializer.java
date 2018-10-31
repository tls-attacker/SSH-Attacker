package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHKeyExchangeInitMessageSerializer extends BinaryPacketSerializer<ECDHKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ECDHKeyExchangeInitMessage msg;

    public ECDHKeyExchangeInitMessageSerializer(ECDHKeyExchangeInitMessage msg) {
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
