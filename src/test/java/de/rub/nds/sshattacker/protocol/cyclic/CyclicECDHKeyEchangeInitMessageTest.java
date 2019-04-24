package de.rub.nds.sshattacker.protocol.cyclic;

import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.parser.ClientInitMessageParserTest;
import de.rub.nds.sshattacker.protocol.parser.EcdhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.protocol.serializer.EcdhKeyExchangeInitMessageSerializer;
import java.util.Collection;
import java.util.LinkedList;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CyclicECDHKeyEchangeInitMessageTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        Collection<Object[]> fullData = ClientInitMessageParserTest.generateData();
        Collection<Object[]> bytesOnly = new LinkedList<>();
        fullData.forEach((obj) -> {
            bytesOnly.add(new Object[]{obj[0]});
        });
        return bytesOnly;
    }

    private final byte[] bytes;

    public CyclicECDHKeyEchangeInitMessageTest(byte[] bytes) {
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
