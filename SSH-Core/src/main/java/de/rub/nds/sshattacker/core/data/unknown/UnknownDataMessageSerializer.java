/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.unknown;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownDataMessageSerializer extends ProtocolMessageSerializer<UnknownDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownDataMessageSerializer(UnknownDataMessage message) {
        super(message);
    }

    @Override
    public final void serializeProtocolMessageContents() {
        byte[] payload = message.getPayload().getValue();
        LOGGER.debug("Payload: {}", () -> ArrayConverter.bytesToHexString(payload));
        appendBytes(payload);
    }
}
