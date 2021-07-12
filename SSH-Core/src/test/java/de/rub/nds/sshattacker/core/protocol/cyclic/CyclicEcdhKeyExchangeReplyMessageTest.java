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

import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.parser.EcdhKeyExchangeReplyMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.serializer.EcdhKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.EcdhKeyExchangeReplyMessageParser;

import java.util.Collection;
import java.util.LinkedList;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CyclicEcdhKeyExchangeReplyMessageTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        Collection<Object[]> fullData = EcdhKeyExchangeReplyMessageParserTest.generateData();
        Collection<Object[]> bytesOnly = new LinkedList<>();
        fullData.forEach((obj) -> bytesOnly.add(new Object[]{obj[0]}));
        return bytesOnly;
    }

    private final byte[] bytes;

    public CyclicEcdhKeyExchangeReplyMessageTest(byte[] bytes) {
        this.bytes = bytes;
    }

    @Test
    public void test() {
        EcdhKeyExchangeReplyMessage msg = new EcdhKeyExchangeReplyMessage();
        new EcdhKeyExchangeReplyMessageParser(0, bytes).parseMessageSpecificPayload(msg);
        byte[] serialized = new EcdhKeyExchangeReplyMessageSerializer(msg).serializeMessageSpecificPayload();
        Assert.assertArrayEquals(bytes, serialized);
    }
}
