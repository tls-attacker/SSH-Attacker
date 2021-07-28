/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.cyclic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthSuccessMessageSerializer;
import org.junit.jupiter.api.Test;

public class CyclicUserAuthSuccessMessageTest {
    /** Cyclic test for parsing and serializing of UserAuthSuccessMessage */
    @Test
    public void testCyclic() {
        byte[] bytes = new byte[] {52};
        UserAuthSuccessMessage message = new UserAuthSuccessMessageParser(0, bytes).parse();
        assertArrayEquals(bytes, new UserAuthSuccessMessageSerializer(message).serialize());
    }
}
