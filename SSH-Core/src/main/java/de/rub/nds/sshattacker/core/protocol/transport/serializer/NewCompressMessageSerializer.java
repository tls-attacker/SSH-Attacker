/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewCompressMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewCompressMessageSerializer extends SshMessageSerializer<NewCompressMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewCompressMessageSerializer(NewCompressMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {}
}
