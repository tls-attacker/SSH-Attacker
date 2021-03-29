/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageParser extends MessageParser<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeInitMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    private void parsePublicKeyLength(EcdhKeyExchangeInitMessage msg) {
        msg.setPublicKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void parsePublicKey(EcdhKeyExchangeInitMessage msg) {
        msg.setPublicKey(parseArrayOrTillEnd(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("PublicKey: " + msg.getPublicKey());
    }

    @Override
    public void parseMessageSpecificPayload(EcdhKeyExchangeInitMessage msg) {
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
    }

    @Override
    public EcdhKeyExchangeInitMessage createMessage() {
        return new EcdhKeyExchangeInitMessage();
    }
}
