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
import de.rub.nds.sshattacker.core.protocol.message.ClientInitMessage;

import java.util.Arrays;
import java.util.Collection;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ClientInitMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { ArrayConverter.hexStringToByteArray("5353482d322e302d4f70656e5353485f372e380d0a"),
                        "SSH-2.0-OpenSSH_7.8", "" },
                { ArrayConverter.hexStringToByteArray("5353482d322e302d6c69627373685f302e372e300d0a"),
                        "SSH-2.0-libssh_0.7.0", "" } });
    }

    private final byte[] message;

    private final String version;
    private final String comment;

    public ClientInitMessageParserTest(byte[] message, String version, String comment) {
        this.message = message;
        this.version = version;
        this.comment = comment;
    }

    /**
     * Test of parse method, of class ClientInitMessageParser.
     */
    @Test
    public void testParse() {
        ClientInitMessageParser parser = new ClientInitMessageParser(0, message);
        ClientInitMessage msg = parser.parse();

        Assert.assertEquals(version, msg.getVersion().getValue());
        Assert.assertEquals(comment, msg.getComment().getValue());
    }
}
