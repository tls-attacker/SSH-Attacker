/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageParser extends MessageParser<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeInitMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parsePublicKey(EcdhKeyExchangeInitMessage msg) {
        msg.setPublicKeyLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Public key length: " + msg.getPublicKeyLength().getValue());
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("Public key: " + ArrayConverter.bytesToRawHexString(msg.getPublicKey().getValue()));
    }

    @Override
    public void parseMessageSpecificPayload(EcdhKeyExchangeInitMessage msg) {
        parsePublicKey(msg);
    }

    @Override
    public EcdhKeyExchangeInitMessage createMessage() {
        return new EcdhKeyExchangeInitMessage();
    }
}
