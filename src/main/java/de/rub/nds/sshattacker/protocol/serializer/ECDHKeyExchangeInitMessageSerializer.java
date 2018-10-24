package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHKeyExchangeInitMessageSerializer extends Serializer<ECDHKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ECDHKeyExchangeInitMessage msg;

    public ECDHKeyExchangeInitMessageSerializer(ECDHKeyExchangeInitMessage msg) {
        this.msg = msg;
    }

    private void serializePublicKeyLength() {
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
        appendInt(msg.getPublicKeyLength().getValue(), 4);
    }

    private void serializePublicKey() {
        LOGGER.debug("PublicKey: " + msg.getPublicKey());
        appendBytes(msg.getPublicKey().getValue());
    }

    @Override
    protected byte[] serializeBytes() {
        serializePublicKeyLength();
        serializePublicKey();
        return getAlreadySerialized();
    }

}
