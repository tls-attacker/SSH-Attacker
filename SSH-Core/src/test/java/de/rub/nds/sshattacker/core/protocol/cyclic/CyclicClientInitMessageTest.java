/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.cyclic;

import de.rub.nds.sshattacker.core.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.core.protocol.parser.ClientInitMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.serializer.ClientInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.ClientInitMessageParser;

import java.util.Collection;
import java.util.LinkedList;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.Test;

@RunWith(Parameterized.class)
public class CyclicClientInitMessageTest {

    final byte[] message;

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        Collection<Object[]> fullData = ClientInitMessageParserTest.generateData();
        Collection<Object[]> bytesOnly = new LinkedList<>();
        fullData.forEach((obj) -> bytesOnly.add(new Object[]{obj[0]}));
        return bytesOnly;
    }

    public CyclicClientInitMessageTest(byte[] message) {
        this.message = message;
    }

    @Test
    public void testCyclic() {
        ClientInitMessage msg = new ClientInitMessageParser(0, message).parse();
        byte[] serialized = new ClientInitMessageSerializer(msg).serialize();
        Assert.assertArrayEquals(serialized, message);
    }
}
