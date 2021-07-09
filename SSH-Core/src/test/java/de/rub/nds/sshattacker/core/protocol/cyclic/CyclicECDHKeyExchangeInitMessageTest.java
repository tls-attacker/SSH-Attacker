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

import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.parser.VersionExchangeMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.serializer.EcdhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.EcdhKeyExchangeInitMessageParser;

import java.util.Collection;
import java.util.LinkedList;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CyclicECDHKeyExchangeInitMessageTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        Collection<Object[]> fullData = VersionExchangeMessageParserTest.generateData();
        Collection<Object[]> bytesOnly = new LinkedList<>();
        fullData.forEach((obj) -> bytesOnly.add(new Object[]{obj[0]}));
        return bytesOnly;
    }

    private final byte[] bytes;

    public CyclicECDHKeyExchangeInitMessageTest(byte[] bytes) {
        this.bytes = bytes;
    }

    @Test
    public void test() {
        EcdhKeyExchangeInitMessage msg = new EcdhKeyExchangeInitMessage();
        new EcdhKeyExchangeInitMessageParser(0, bytes).parseMessageSpecificPayload(msg);
        byte[] serialized = new EcdhKeyExchangeInitMessageSerializer(msg).serializeMessageSpecificPayload();
        Assert.assertArrayEquals(bytes, serialized);
    }
}
