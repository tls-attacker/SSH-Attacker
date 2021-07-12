/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.parser.EcdhKeyExchangeInitMessageParserTest;
import java.util.Collection;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class EcdhKeyExchangeInitMessageSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return EcdhKeyExchangeInitMessageParserTest.generateData();
    }

    private final byte[] bytes;

    private final int publicKeyLength;
    private final byte[] publicKey;

    public EcdhKeyExchangeInitMessageSerializerTest(byte[] bytes, int publicKeyLength, byte[] publicKey) {
        this.bytes = bytes;
        this.publicKeyLength = publicKeyLength;
        this.publicKey = publicKey;
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of serializeBytes method, of class EcdhKeyExchangeInitMessageSerializer.
     */
    @Test
    public void testSerializeMessageSpecificPayload() {
        EcdhKeyExchangeInitMessage msg = new EcdhKeyExchangeInitMessage();
        msg.setPublicKeyLength(publicKeyLength);
        msg.setPublicKey(publicKey);

        EcdhKeyExchangeInitMessageSerializer serializer = new EcdhKeyExchangeInitMessageSerializer(msg);

        assertArrayEquals(bytes, serializer.serializeMessageSpecificPayload());
    }

}
