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

    public EcdhKeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public EcdhKeyExchangeInitMessage createMessage() {
        return new EcdhKeyExchangeInitMessage();
    }

    private void parsePublicKey() {
        message.setPublicKeyLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Public key length: " + message.getPublicKeyLength().getValue());
        message.setPublicKey(parseByteArrayField(message.getPublicKeyLength().getValue()));
        LOGGER.debug(
                "Public key: "
                        + ArrayConverter.bytesToRawHexString(message.getPublicKey().getValue()));
    }

    @Override
    public void parseMessageSpecificContents() {
        parsePublicKey();
    }
}
