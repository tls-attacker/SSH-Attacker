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
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessageParser
        extends SshMessageParser<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeInitMessageParser(byte[] array) {
        super(array);
    }

    public HybridKeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseHybridKey() {
        int length = parseIntField();
        LOGGER.debug("ConcatenatedHybridKeys Length: {}", length);
        message.setConcatenatedHybridKeysLength(length);

        byte[] concatenatedHybridKeys = parseByteArrayField(length);
        LOGGER.debug(
                "ConcatenatedHybridKeys: {}",
                () -> ArrayConverter.bytesToRawHexString(concatenatedHybridKeys));
        message.setConcatenatedHybridKeys(concatenatedHybridKeys);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHybridKey();
    }

    @Override
    protected HybridKeyExchangeInitMessage createMessage() {
        return new HybridKeyExchangeInitMessage();
    }
}
