/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;

public class ExtensionInfoMessageSerializer extends SshMessageSerializer<ExtensionInfoMessage> {
    public ExtensionInfoMessageSerializer(ExtensionInfoMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {
        // TODO: Implement serializer
    }
}
