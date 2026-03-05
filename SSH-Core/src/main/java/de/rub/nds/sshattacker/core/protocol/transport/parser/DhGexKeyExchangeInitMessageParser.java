/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessageParser
        extends SshMessageParser<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeInitMessageParser(byte[] array) {
        super(array);
    }

    public DhGexKeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected DhGexKeyExchangeInitMessage createMessage() {
        return new DhGexKeyExchangeInitMessage();
    }

    private void parseEphemeralPublicKey() {
        int ephemeralPublicKeyLength = parseIntField();
        message.setEphemeralPublicKeyLength(ephemeralPublicKeyLength);
        LOGGER.debug("Ephemeral public key (client) length: {}", ephemeralPublicKeyLength);
        BigInteger ephemeralPublicKey = parseBigIntField(ephemeralPublicKeyLength);
        message.setEphemeralPublicKey(ephemeralPublicKey);
        LOGGER.debug("Ephemeral public key (client): {}", ephemeralPublicKey);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseEphemeralPublicKey();
    }
}
