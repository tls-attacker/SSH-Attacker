/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.message.DhGexKeyExchangeGroupMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeGroupMessageParser extends MessageParser<DhGexKeyExchangeGroupMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeGroupMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseGroupModulusLength(DhGexKeyExchangeGroupMessage msg) {
        msg.setGroupModulusLength(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Group modulus length: " + msg.getGroupModulusLength().getValue());
    }

    private void parseGroupModulus(DhGexKeyExchangeGroupMessage msg) {
        msg.setGroupModulus(parseBigIntField(msg.getGroupModulusLength().getValue()));
        LOGGER.debug("Group modulus: " + ArrayConverter.bytesToRawHexString(msg.getGroupModulus().getByteArray()));
    }

    private void parseGroupGeneratorLength(DhGexKeyExchangeGroupMessage msg) {
        msg.setGroupGeneratorLength(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Group generator length: " + msg.getGroupGeneratorLength().getValue());
    }

    private void parseGroupGenerator(DhGexKeyExchangeGroupMessage msg) {
        msg.setGroupGenerator(parseBigIntField(msg.getGroupGeneratorLength().getValue()));
        LOGGER.debug("Group generator: " + ArrayConverter.bytesToRawHexString(msg.getGroupGenerator().getByteArray()));
    }

    @Override
    protected void parseMessageSpecificPayload(DhGexKeyExchangeGroupMessage msg) {
        parseGroupModulusLength(msg);
        parseGroupModulus(msg);
        parseGroupGeneratorLength(msg);
        parseGroupGenerator(msg);
    }

    @Override
    public DhGexKeyExchangeGroupMessage createMessage() {
        return new DhGexKeyExchangeGroupMessage();
    }
}
