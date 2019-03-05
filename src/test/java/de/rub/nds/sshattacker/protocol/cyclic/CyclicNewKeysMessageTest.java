//package de.rub.nds.sshattacker.protocol.cyclic;
//
//import java.util.Collection;
//import java.util.LinkedList;
//import org.junit.runner.RunWith;
//import org.junit.runners.Parameterized;
//
//@RunWith(Parameterized.class)
//public class CyclicNewKeysMessageTest {
//
//    @Parameterized.Parameters
//    public static Collection<Object[]> generateData() {
//        Collection<Object[]> fullData = NewKeysMessageParserTest.generateData();
//        Collection<Object[]> bytesOnly = new LinkedList<>();
//        fullData.forEach((obj) -> {
//            bytesOnly.add(new Object[] {obj[0]});
//        });
//        return bytesOnly;
//    }
//}
