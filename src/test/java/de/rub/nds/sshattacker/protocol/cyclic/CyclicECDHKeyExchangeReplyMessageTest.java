package de.rub.nds.sshattacker.protocol.cyclic;

import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.protocol.parser.ECDHKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.protocol.parser.ECDHKeyExchangeReplyMessageParserTest;
import de.rub.nds.sshattacker.protocol.serializer.ECDHKeyExchangeReplyMessageSerializer;
import java.util.Collection;
import java.util.LinkedList;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CyclicECDHKeyExchangeReplyMessageTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        Collection<Object[]> fullData = ECDHKeyExchangeReplyMessageParserTest.generateData();
        Collection<Object[]> bytesOnly = new LinkedList<>();
        fullData.forEach((obj) -> {
            bytesOnly.add(new Object[]{obj[0]});
        });
        return bytesOnly;
    }

    private final byte[] bytes;

    public CyclicECDHKeyExchangeReplyMessageTest(byte[] bytes){
        this.bytes = bytes;
    }
    
    @Test
    public void test(){
        ECDHKeyExchangeReplyMessage msg = new ECDHKeyExchangeReplyMessageParser(0, bytes).parseMessageSpecificPayload();
        byte[] serialized = new ECDHKeyExchangeReplyMessageSerializer(msg).serializeMessageSpecificPayload();
        Assert.assertArrayEquals(bytes, serialized);
    }
}
