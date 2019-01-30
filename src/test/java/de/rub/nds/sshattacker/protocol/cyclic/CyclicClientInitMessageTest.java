package de.rub.nds.sshattacker.protocol.cyclic;

import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.parser.ClientInitMessageParser;
import de.rub.nds.sshattacker.protocol.parser.ClientInitMessageParserTest;
import de.rub.nds.sshattacker.protocol.serializer.ClientInitMessageSerializer;
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
        fullData.forEach((obj) -> {
            bytesOnly.add(new Object[] {obj[0]});
        });
        return bytesOnly;
    }
    
    public CyclicClientInitMessageTest(byte[] message) {
        this.message = message;
    }
    
    @Test
    public void testCyclic(){
        ClientInitMessage msg = new ClientInitMessageParser(0, message).parse();
        byte[] serialized = new ClientInitMessageSerializer(msg).serialize();
        Assert.assertArrayEquals(serialized, message);
    }
}
