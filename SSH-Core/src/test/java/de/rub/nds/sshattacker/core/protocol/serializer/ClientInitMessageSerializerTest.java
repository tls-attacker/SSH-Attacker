/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.core.protocol.parser.ClientInitMessageParserTest;
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
public class ClientInitMessageSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ClientInitMessageParserTest.generateData();
    }

    private final String version;
    private final String comment;

    private final byte[] bytes;

    public ClientInitMessageSerializerTest(byte[] bytes, String version, String comment) {
        this.bytes = bytes;
        this.version = version;
        this.comment = comment;
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

    @Test
    public void testSerializeBytes() {
        ClientInitMessage msg = new ClientInitMessage();
        msg.setVersion(version);
        msg.setComment(comment);
        ClientInitMessageSerializer serializer = new ClientInitMessageSerializer(msg);
        assertArrayEquals(bytes, serializer.serialize());
    }
}
