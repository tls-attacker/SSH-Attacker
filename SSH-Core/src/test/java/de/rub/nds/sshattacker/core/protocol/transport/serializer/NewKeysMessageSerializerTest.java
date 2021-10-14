/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import org.junit.jupiter.api.Test;

public class NewKeysMessageSerializerTest {
    /** Test of NewKeysMessageSerializer::serialize method */
    @Test
    public void testSerialize() {
        NewKeysMessage msg = new NewKeysMessage();
        assertArrayEquals(new byte[] {21}, new NewKeysMessageSerializer(msg).serialize());
    }
}
