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

import de.rub.nds.sshattacker.core.protocol.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.parser.VersionExchangeMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.serializer.VersionExchangeMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.VersionExchangeMessageParser;

import java.util.Collection;
import java.util.LinkedList;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.Test;

@RunWith(Parameterized.class)
public class CyclicVersionExchangeMessageTest {

    final byte[] message;

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        Collection<Object[]> fullData = VersionExchangeMessageParserTest.generateData();
        Collection<Object[]> bytesOnly = new LinkedList<>();
        fullData.forEach((obj) -> bytesOnly.add(new Object[]{obj[0]}));
        return bytesOnly;
    }

    public CyclicVersionExchangeMessageTest(byte[] message) {
        this.message = message;
    }

    @Test
    public void testCyclic() {
        VersionExchangeMessage msg = new VersionExchangeMessageParser(0, message).parse();
        byte[] serialized = new VersionExchangeMessageSerializer(msg).serialize();
        Assert.assertArrayEquals(serialized, message);
    }
}
