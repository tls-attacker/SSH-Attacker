/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeGroupMessageParser
        extends SshMessageParser<DhGexKeyExchangeGroupMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeGroupMessageParser(byte[] array) {
        super(array);
    }

    public DhGexKeyExchangeGroupMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeGroupMessage createMessage() {
        return new DhGexKeyExchangeGroupMessage();
    }

    private void parseGroupModulus() {
        int groupModulusLength = parseIntField();
        message.setGroupModulusLength(groupModulusLength);
        LOGGER.debug("Group modulus length: {}", groupModulusLength);
        BigInteger groupModulus = parseBigIntField(groupModulusLength);
        message.setGroupModulus(groupModulus);
        LOGGER.debug(
                "Group modulus: {}",
                () ->
                        ArrayConverter.bytesToRawHexString(
                                ArrayConverter.bigIntegerToByteArray(groupModulus)));
    }

    private void parseGroupGenerator() {
        int groupGeneratorLength = parseIntField();
        message.setGroupGeneratorLength(groupGeneratorLength);
        LOGGER.debug("Group generator length: {}", groupGeneratorLength);
        BigInteger groupGenerator = parseBigIntField(groupGeneratorLength);
        message.setGroupGenerator(groupGenerator);
        LOGGER.debug(
                "Group generator: {}",
                () ->
                        ArrayConverter.bytesToRawHexString(
                                ArrayConverter.bigIntegerToByteArray(groupGenerator)));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseGroupModulus();
        parseGroupGenerator();
    }
}
