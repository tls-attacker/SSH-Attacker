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
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageParser extends SshMessageParser<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeInitMessageParser(byte[] array) {
        super(array);
    }

    public EcdhKeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public EcdhKeyExchangeInitMessage createMessage() {
        return new EcdhKeyExchangeInitMessage();
    }

    private void parseEphemeralPublicKey() {
        int ephemeralPublicKeyLength = parseIntField();
        message.setEphemeralPublicKeyLength(ephemeralPublicKeyLength);
        LOGGER.debug("Ephemeral public key (client) length: {}", ephemeralPublicKeyLength);
        byte[] ephemeralPublicKey = parseByteArrayField(ephemeralPublicKeyLength);
        message.setEphemeralPublicKey(ephemeralPublicKey);
        LOGGER.debug(
                "Ephemeral public key (client): {}",
                () -> ArrayConverter.bytesToRawHexString(ephemeralPublicKey));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseEphemeralPublicKey();
    }
}
