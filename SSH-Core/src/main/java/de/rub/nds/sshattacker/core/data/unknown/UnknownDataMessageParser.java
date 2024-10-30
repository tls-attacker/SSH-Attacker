/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.unknown;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownDataMessageParser extends ProtocolMessageParser<UnknownDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownDataMessageParser(byte[] array) {
        super(array);
    }

    public UnknownDataMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UnknownDataMessage createMessage() {
        return new UnknownDataMessage();
    }

    @Override
    public void parseProtocolMessageContents() {
        message.setPayload(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Payload: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getPayload().getValue()));
    }
}
