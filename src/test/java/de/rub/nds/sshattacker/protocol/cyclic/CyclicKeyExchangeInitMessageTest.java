package de.rub.nds.sshattacker.protocol.cyclic;

import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.parser.KeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.protocol.parser.KeyExchangeInitMessageParserTest;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import java.util.Collection;
import java.util.LinkedList;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CyclicKeyExchangeInitMessageTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        Collection<Object[]> fullData = KeyExchangeInitMessageParserTest.generateData();
        Collection<Object[]> bytesOnly = new LinkedList<>();
        fullData.forEach((obj) -> {
            bytesOnly.add(new Object[] {obj[0]});
        });
        return bytesOnly;
    }
    
    private final byte[] bytes;

    public CyclicKeyExchangeInitMessageTest(byte[] bytes) {
        this.bytes = bytes;
    }
    
    @Test
    public void test(){
        KeyExchangeInitMessage msg = new KeyExchangeInitMessageParser(0,bytes).parseMessageSpecificPayload();
        byte[] serialized = new KeyExchangeInitMessageSerializer(msg).serializeMessageSpecificPayload();
        Assert.assertArrayEquals(bytes, serialized);
    }
}
