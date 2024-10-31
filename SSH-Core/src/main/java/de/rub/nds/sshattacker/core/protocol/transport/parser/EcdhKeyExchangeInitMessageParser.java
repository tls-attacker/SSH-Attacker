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
        message.setEphemeralPublicKeyLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Ephemeral public key (client) length: {}",
                message.getEphemeralPublicKeyLength().getValue());
        message.setEphemeralPublicKey(
                parseByteArrayField(message.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug(
                "Ephemeral public key (client): {}",
                () ->
                        ArrayConverter.bytesToRawHexString(
                                message.getEphemeralPublicKey().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseEphemeralPublicKey();
    }
}
