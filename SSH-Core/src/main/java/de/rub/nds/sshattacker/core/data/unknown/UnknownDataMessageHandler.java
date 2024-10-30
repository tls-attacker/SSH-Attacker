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

public class UnknownDataMessageHandler extends ProtocolMessageHandler<UnknownDataMessage> {

    public UnknownDataMessageHandler(SshContext context) {
        super(context);
    }

    public UnknownDataMessageHandler(SshContext context, UnknownDataMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        LOGGER.debug(
                "Received unknown data message:\n{}",
                () -> ArrayConverter.bytesToHexString(message.getPayload()));
    }

    @Override
    public UnknownDataMessageParser getParser(byte[] array) {
        return new UnknownDataMessageParser(array);
    }

    @Override
    public UnknownDataMessageParser getParser(byte[] array, int startPosition) {
        return new UnknownDataMessageParser(array, startPosition);
    }

    @Override
    public UnknownDataMessagePreparator getPreparator() {
        return new UnknownDataMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UnknownDataMessageSerializer getSerializer() {
        return new UnknownDataMessageSerializer(message);
    }
}
