package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.protocol.core.message.Parser;
import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHKeyExchangeInitMessageParser extends Parser<ECDHKeyExchangeInitMessage> {

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
    public ECDHKeyExchangeInitMessage parse() {
        ECDHKeyExchangeInitMessage msg = new ECDHKeyExchangeInitMessage();
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
        return msg;
    }

}
