/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewKeysMessageSerializer;
import org.junit.jupiter.api.Test;

public class CyclicNewKeysMessageTest {
    /** Cyclic test for parsing and serializing of NewKeysMessage */
    @Test
    public void testCyclic() {
        byte[] bytes = new byte[] {21};
        NewKeysMessage message = new NewKeysMessageParser(0, bytes).parse();
        assertArrayEquals(bytes, new NewKeysMessageSerializer(message).serialize());
    }
}
