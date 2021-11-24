/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthSuccessMessageHandler extends SshMessageHandler<UserAuthSuccessMessage> {

    public UserAuthSuccessMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthSuccessMessageHandler(SshContext context, UserAuthSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // Enable delayed compression if negotiated
        activateCompression();
    }

    private void activateCompression() {
        if (context.getCompressionMethodClientToServer().orElse(CompressionMethod.NONE)
                == CompressionMethod.ZLIB_OPENSSH_COM) {
            context.getPacketLayer()
                    .updateCompressionAlgorithm(
                            context.getCompressionMethodClientToServer().get().getAlgorithm());
        }
        if (context.getCompressionMethodServerToClient().orElse(CompressionMethod.NONE)
                == CompressionMethod.ZLIB_OPENSSH_COM) {
            context.getPacketLayer()
                    .updateDecompressionAlgorithm(
                            context.getCompressionMethodServerToClient().get().getAlgorithm());
        }
    }

    @Override
    public UserAuthSuccessMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthSuccessMessageParser(array, startPosition);
    }

    @Override
    public UserAuthSuccessMessagePreparator getPreparator() {
        return new UserAuthSuccessMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthSuccessMessageSerializer getSerializer() {
        return new UserAuthSuccessMessageSerializer(message);
    }
}
