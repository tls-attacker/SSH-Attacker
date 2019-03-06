package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHKeyExchangeInitMessageParser extends MessageParser<ECDHKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECDHKeyExchangeInitMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    private void parsePublicKeyLength(ECDHKeyExchangeInitMessage msg) {
        msg.setPublicKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void parsePublicKey(ECDHKeyExchangeInitMessage msg) {
        msg.setPublicKey(parseArrayOrTillEnd(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("PublicKey: " + msg.getPublicKey());
    }

    @Override
    public void parseMessageSpecificPayload(ECDHKeyExchangeInitMessage msg) {
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
    }

    @Override
    public ECDHKeyExchangeInitMessage createMessage() {
        return new ECDHKeyExchangeInitMessage();
    }
}
