/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class RsaKeyExchangeSecretMessageSerializerTest {

    /**
     * Provides a stream of test vectors for the RsaKeyExchangeSecretMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "1F0000010048A2B309ACBAD2DAF99E9B37E7D7A68ACA8EF04FA3BD75E0410C440D880A9DFC3E2EED323554F2CDCD2EB2968131BC146D9B06277C8C39A884BB80285FC5C2EDFCEF7C1549013F68D2BE7E8B959F3CC68150514F2B1E9D623F7AC9EFCDC5A22514AE8ECEE3380A03049B7FA426550ADC93A8266218329C4B23ED9C5C79E10975D7558C9D3917063DC5A8E270F274F63944E53FA9D40B84591C1EA0736F2972E1243F660377990DA3BBD7A8062F2EC34E70B09EB88EFE6D00416BD2C79B809C82D0292BF3BFCF651992660E644E36D725BEA0BE65C92D9519D649219D57CF6EF9C382D9BD9A500BF36DBA9174CB8F25E6CD858CE87CF43C508A8E3EA2BC3E50A0"),
                        256, // Encrypted Secret Length
                        ArrayConverter.hexStringToByteArray(
                                "48A2B309ACBAD2DAF99E9B37E7D7A68ACA8EF04FA3BD75E0410C440D880A9DFC3E2EED323554F2CDCD2EB2968131BC146D9B06277C8C39A884BB80285FC5C2EDFCEF7C1549013F68D2BE7E8B959F3CC68150514F2B1E9D623F7AC9EFCDC5A22514AE8ECEE3380A03049B7FA426550ADC93A8266218329C4B23ED9C5C79E10975D7558C9D3917063DC5A8E270F274F63944E53FA9D40B84591C1EA0736F2972E1243F660377990DA3BBD7A8062F2EC34E70B09EB88EFE6D00416BD2C79B809C82D0292BF3BFCF651992660E644E36D725BEA0BE65C92D9519D649219D57CF6EF9C382D9BD9A500BF36DBA9174CB8F25E6CD858CE87CF43C508A8E3EA2BC3E50A0")));
    }

    /**
     * Test of RsaKeyExchangeSecretMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output of the serialize() call
     * @param providedEncryptedSecretLength Length of the encrypted secret
     * @param providedEncryptedSecret Bytes of the encrypted secret
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedEncryptedSecretLength,
            byte[] providedEncryptedSecret) {
        RsaKeyExchangeSecretMessage msg = new RsaKeyExchangeSecretMessage();

        msg.setMessageId(MessageIdConstant.SSH_MSG_KEXRSA_SECRET);
        msg.setEncryptedSecretLength(providedEncryptedSecretLength);
        msg.setEncryptedSecret(providedEncryptedSecret);
        RsaKeyExchangeSecretMessageSerializer serializer =
                new RsaKeyExchangeSecretMessageSerializer();

        assertArrayEquals(expectedBytes, serializer.serialize(msg));
    }
}
