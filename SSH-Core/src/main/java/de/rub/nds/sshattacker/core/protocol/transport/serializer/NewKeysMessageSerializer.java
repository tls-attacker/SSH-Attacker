/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;

public class NewKeysMessageSerializer extends MessageSerializer<NewKeysMessage> {

    public NewKeysMessageSerializer(NewKeysMessage msg) {
        super(msg);
    }

    @Override
    protected void serializeMessageSpecificPayload() {}
}
