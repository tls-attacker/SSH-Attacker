/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewKeysMessageSerializer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class NewKeysMessageSerializerTest {
    /**
     * Test of NewKeysMessageSerializer::serialize method
     */
    @Test
    public void testSerialize() {
        NewKeysMessage msg = new NewKeysMessage();
        assertArrayEquals(new byte[] { 21 }, new NewKeysMessageSerializer(msg).serialize());
    }
}
