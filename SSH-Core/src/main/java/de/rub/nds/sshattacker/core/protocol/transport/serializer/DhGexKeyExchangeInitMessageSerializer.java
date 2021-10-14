/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeInitMessageSerializer(DhGexKeyExchangeInitMessage message) {
        super(message);
    }

    private void serializePublicKey() {
        LOGGER.debug("Public key length: " + message.getPublicKeyLength().getValue());
        appendInt(message.getPublicKeyLength().getValue(), DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Public key: " + message.getPublicKey().getValue());
        appendBytes(message.getPublicKey().getValue().toByteArray());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializePublicKey();
    }
}
