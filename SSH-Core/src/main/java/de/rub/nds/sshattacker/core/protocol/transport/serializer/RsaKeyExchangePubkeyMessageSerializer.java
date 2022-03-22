/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangePubkeyMessageSerializer
        extends SshMessageSerializer<RsaKeyExchangePubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangePubkeyMessageSerializer(RsaKeyExchangePubkeyMessage message) {
        super(message);
    }

    public void serializeHostKey() {
        LOGGER.debug("Host key: " + message.getHostKey());
        appendBytes(message.getHostKey().getValue());
    }

    public void serializeTransientPublicKey() {
        LOGGER.debug("Transient public key: " + message.getTransientPublicKey());
        appendBytes(message.getTransientPublicKey().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeHostKey();
        serializeTransientPublicKey();
    }
}
