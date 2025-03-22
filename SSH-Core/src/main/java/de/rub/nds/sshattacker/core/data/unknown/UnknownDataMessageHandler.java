/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.unknown;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownDataMessageHandler extends ProtocolMessageHandler<UnknownDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, UnknownDataMessage object) {
        LOGGER.debug(
                "Received unknown data message:\n{}",
                () -> ArrayConverter.bytesToHexString(object.getPayload()));
    }

    @Override
    public UnknownDataMessageParser getParser(byte[] array, SshContext context) {
        return new UnknownDataMessageParser(array);
    }

    @Override
    public UnknownDataMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new UnknownDataMessageParser(array, startPosition);
    }

    public static final UnknownDataMessagePreparator PREPARATOR =
            new UnknownDataMessagePreparator();

    public static final UnknownDataMessageSerializer SERIALIZER =
            new UnknownDataMessageSerializer();
}
