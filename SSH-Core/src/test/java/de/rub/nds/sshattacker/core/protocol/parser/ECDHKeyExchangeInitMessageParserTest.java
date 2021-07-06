/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeInitMessage;

import java.util.Arrays;
import java.util.Collection;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECDHKeyExchangeInitMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("00000020c3579aa0b92395e888ed16a546587c5d8879f0f2f813b2bc68bab3325b9a6f0f"),
                        32,
                        ArrayConverter
                                .hexStringToByteArray("c3579aa0b92395e888ed16a546587c5d8879f0f2f813b2bc68bab3325b9a6f0f") }, });
    }

    private final byte[] bytes;
    private final int publicKeyLength;
    private final byte[] publicKey;

    public ECDHKeyExchangeInitMessageParserTest(byte[] bytes, int publicKeyLength, byte[] publicKey) {
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
     * Test of parse method, of class EcdhKeyExchangeInitMessageParser.
     */
    @Test
    public void testParseMessageSpecificPayload() {
        EcdhKeyExchangeInitMessageParser parser = new EcdhKeyExchangeInitMessageParser(0, bytes);
        EcdhKeyExchangeInitMessage msg = new EcdhKeyExchangeInitMessage();
        parser.parseMessageSpecificPayload(msg);
        assertEquals(publicKeyLength, msg.getPublicKeyLength().getValue().intValue());
        assertArrayEquals(publicKey, msg.getPublicKey().getValue());

    }

}
