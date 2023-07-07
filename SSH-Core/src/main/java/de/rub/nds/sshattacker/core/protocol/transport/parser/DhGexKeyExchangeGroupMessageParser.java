/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeGroupMessageParser
        extends SshMessageParser<DhGexKeyExchangeGroupMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*    public DhGexKeyExchangeGroupMessageParser(byte[] array) {
        super(array);
    }

    public DhGexKeyExchangeGroupMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/

    public DhGexKeyExchangeGroupMessageParser(InputStream stream) {
        super(stream);
    }

    /*    @Override
    public DhGexKeyExchangeGroupMessage createMessage() {
        return new DhGexKeyExchangeGroupMessage();
    }*/

    private void parseGroupModulus(DhGexKeyExchangeGroupMessage message) {
        message.setGroupModulusLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Group modulus length: " + message.getGroupModulusLength().getValue());
        message.setGroupModulus(parseBigIntField(message.getGroupModulusLength().getValue()));
        LOGGER.debug(
                "Group modulus: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getGroupModulus().getByteArray()));
    }

    private void parseGroupGenerator(DhGexKeyExchangeGroupMessage message) {
        message.setGroupGeneratorLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Group generator length: " + message.getGroupGeneratorLength().getValue());
        message.setGroupGenerator(parseBigIntField(message.getGroupGeneratorLength().getValue()));
        LOGGER.debug(
                "Group generator: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getGroupGenerator().getByteArray()));
    }

    @Override
    protected void parseMessageSpecificContents(DhGexKeyExchangeGroupMessage message) {
        parseGroupModulus(message);
        parseGroupGenerator(message);
    }

    @Override
    public void parse(DhGexKeyExchangeGroupMessage message) {
        parseProtocolMessageContents(message);
    }
}
