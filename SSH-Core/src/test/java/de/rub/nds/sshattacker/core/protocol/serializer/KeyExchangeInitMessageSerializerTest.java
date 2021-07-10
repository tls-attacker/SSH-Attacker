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

import de.rub.nds.sshattacker.core.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.parser.KeyExchangeInitMessageParserTest;
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
public class KeyExchangeInitMessageSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return KeyExchangeInitMessageParserTest.generateData();
    }

    private final byte[] bytes;

    private final byte[] cookie;
    private final int keyExchangeAlgorithmsLength;
    private final String keyExchangeAlgorithms;
    private final int serverHostKeyAlgorithmsLength;
    private final String serverHostKeyAlgorithms;
    private final int encryptionAlgorithmsClientToServerLength;
    private final String encryptionAlgorithmsClientToServer;
    private final int encryptionAlgorithmsServerToClientLength;
    private final String encryptionAlgorithmsServerToClient;
    private final int macAlgorithmsClientToServerLength;
    private final String macAlgorithmsClientToServer;
    private final int macAlgorithmsServerToClientLength;
    private final String macAlgorithmsServerToClient;
    private final int compressionAlgorithmsClientToServerLength;
    private final String compressionAlgorithmsClientToServer;
    private final int compressionAlgorithmsServerToClientLength;
    private final String compressionAlgorithmsServerToClient;
    private final int languagesClientToServerLength;
    private final String languagesClientToServer;
    private final int languagesServerToClientLength;
    private final String languagesServerToClient;
    private final boolean firstKeyExchangePacketFollows;
    private final int reserved;

    public KeyExchangeInitMessageSerializerTest(byte[] bytes, byte[] cookie, int keyExchangeAlgorithmsLength,
            String keyExchangeAlgorithms, int serverHostKeyAlgorithmsLength, String serverHostKeyAlgorithms,
            int encryptionAlgorithmsClientToServerLength, String encryptionAlgorithmsClientToServer,
            int encryptionAlgorithmsServerToClientLength, String encryptionAlgorithmsServerToClient,
            int macAlgorithmsClientToServerLength, String macAlgorithmsClientToServer,
            int macAlgorithmsServerToClientLength, String macAlgorithmsServerToClient,
            int compressionAlgorithmsClientToServerLength, String compressionAlgorithmsClientToServer,
            int compressionAlgorithmsServerToClientLength, String compressionAlgorithmsServerToClient,
            int languagesClientToServerLength, String languagesClientToServer, int languagesServerToClientLength,
            String languagesServerToClient, boolean firstKeyExchangePacketFollows, int reserved) {
        this.bytes = bytes;
        this.cookie = cookie;
        this.keyExchangeAlgorithmsLength = keyExchangeAlgorithmsLength;
        this.keyExchangeAlgorithms = keyExchangeAlgorithms;
        this.serverHostKeyAlgorithmsLength = serverHostKeyAlgorithmsLength;
        this.serverHostKeyAlgorithms = serverHostKeyAlgorithms;
        this.encryptionAlgorithmsClientToServerLength = encryptionAlgorithmsClientToServerLength;
        this.encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer;
        this.encryptionAlgorithmsServerToClientLength = encryptionAlgorithmsServerToClientLength;
        this.encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient;
        this.macAlgorithmsClientToServerLength = macAlgorithmsClientToServerLength;
        this.macAlgorithmsClientToServer = macAlgorithmsClientToServer;
        this.macAlgorithmsServerToClientLength = macAlgorithmsServerToClientLength;
        this.macAlgorithmsServerToClient = macAlgorithmsServerToClient;
        this.compressionAlgorithmsClientToServerLength = compressionAlgorithmsClientToServerLength;
        this.compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer;
        this.compressionAlgorithmsServerToClientLength = compressionAlgorithmsServerToClientLength;
        this.compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient;
        this.languagesClientToServerLength = languagesClientToServerLength;
        this.languagesClientToServer = languagesClientToServer;
        this.languagesServerToClientLength = languagesServerToClientLength;
        this.languagesServerToClient = languagesServerToClient;
        this.firstKeyExchangePacketFollows = firstKeyExchangePacketFollows;
        this.reserved = reserved;
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
     * Test of serializeBytes method, of class KeyExchangeInitMessageSerializer.
     */
    @Test
    public void testSerializeMessageSpecificPayload() {
        KeyExchangeInitMessage msg = new KeyExchangeInitMessage();
        msg.setCookie(cookie);
        msg.setKeyExchangeAlgorithmsLength(keyExchangeAlgorithmsLength);
        msg.setKeyExchangeAlgorithms(keyExchangeAlgorithms);
        msg.setServerHostKeyAlgorithmsLength(serverHostKeyAlgorithmsLength);
        msg.setServerHostKeyAlgorithms(serverHostKeyAlgorithms);
        msg.setEncryptionAlgorithmsClientToServerLength(encryptionAlgorithmsClientToServerLength);
        msg.setEncryptionAlgorithmsClientToServer(encryptionAlgorithmsClientToServer);
        msg.setEncryptionAlgorithmsServerToClientLength(encryptionAlgorithmsServerToClientLength);
        msg.setEncryptionAlgorithmsServerToClient(encryptionAlgorithmsServerToClient);
        msg.setMacAlgorithmsClientToServerLength(macAlgorithmsClientToServerLength);
        msg.setMacAlgorithmsClientToServer(macAlgorithmsClientToServer);
        msg.setMacAlgorithmsServerToClientLength(macAlgorithmsServerToClientLength);
        msg.setMacAlgorithmsServerToClient(macAlgorithmsServerToClient);
        msg.setCompressionAlgorithmsClientToServerLength(compressionAlgorithmsClientToServerLength);
        msg.setCompressionAlgorithmsClientToServer(compressionAlgorithmsClientToServer);
        msg.setCompressionAlgorithmsServerToClientLength(compressionAlgorithmsServerToClientLength);
        msg.setCompressionAlgorithmsServerToClient(compressionAlgorithmsServerToClient);
        msg.setLanguagesClientToServerLength(languagesClientToServerLength);
        msg.setLanguagesClientToServer(languagesClientToServer);
        msg.setLanguagesServerToClientLength(languagesServerToClientLength);
        msg.setLanguagesServerToClient(languagesServerToClient);
        msg.setFirstKeyExchangePacketFollows(firstKeyExchangePacketFollows);
        msg.setReserved(reserved);

        KeyExchangeInitMessageSerializer serializer = new KeyExchangeInitMessageSerializer(msg);
        assertArrayEquals(bytes, serializer.serializeMessageSpecificPayload());
    }

}
