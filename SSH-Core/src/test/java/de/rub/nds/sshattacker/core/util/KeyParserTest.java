/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.util;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.keys.*;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

public class KeyParserTest {
    private static final Logger LOGGER = LogManager.getLogger();

    // sshkey generated with "openssl ecparam -name secp521r1 -genkey -out key.pem"
    // pubkey for authorized_keys file on host generated with "ssh-keygen -y -f
    // key.pem >
    // key.pub"
    private List<SshPublicKey<?, ?>> userKeys =
            List.of(
                    new SshPublicKey<>(
                            PublicKeyFormat.SSH_RSA,
                            new CustomRsaPublicKey(
                                    new BigInteger("10001", 16),
                                    new BigInteger(
                                            "009df0c70638448afef5799bc7c161d5bc286baeb8a4dc70ffefb2f4813a"
                                                    + "810747d3cbfcd1c9a9ce76272731ed1e2c0ba64feb9af634ae8e4df699b2"
                                                    + "d3b52af4df616ca8003502e38b81bfa6801148c7bab1870a694b44d82ff0"
                                                    + "98633edb09bfbab52b3e7498ce1826813da010000f7c458877f859f46442"
                                                    + "0853220d632d9d1fc113e885e631f15dfcf1fddba90c0c5aa520bc6a55a5"
                                                    + "6a1b29ead5492f83fe7e6b9494afbe16615daa446c2909c218dcd750ae4a"
                                                    + "9a9c69c74d748e904ba8e2ce2812d1ce3c4ed12fd82cca7fe81f88823907"
                                                    + "6702656ef1d3f93e472aae509a0ae5e241c4fd9b661f4cc6ffb02d416a72"
                                                    + "5469e51e27204b3db3f28961e244a9e6c3",
                                            16)),
                            new CustomRsaPrivateKey(
                                    new BigInteger(
                                            "008701ebcef848371c8c0f40c77719bf4f50aa03b7984d4b56abba286152"
                                                    + "f63a97fe86ef7d10ca534f1256e1c99432085f490fd7edbfc8baa2103aff"
                                                    + "ef127d3ec6b80bde6c16e47a47a54882f614504752e22fd20981aabeb5f4"
                                                    + "0eff3f1a9371ce12d17d58c3c9e04101d700bccca070152bfb8952b3a304"
                                                    + "0303b5270671564f6e2753e05e413931e22a6b115fd3264fd6e4c25cb901"
                                                    + "ccdd006d9b5785379f7cbcc1bbd149afda6b51fe13430fb5ca19da594afc"
                                                    + "cd2bd99473001e995033116d48d329d42255ef0eec11a6d2310eb97912d7"
                                                    + "19b7b75d74696613e21305da6715846bf04c4e76046fbf86a793d96c0fe7"
                                                    + "02638696eed4b7488c18233db879e70149",
                                            16),
                                    new BigInteger(
                                            "009df0c70638448afef5799bc7c161d5bc286baeb8a4dc70ffefb2f4813a"
                                                    + "810747d3cbfcd1c9a9ce76272731ed1e2c0ba64feb9af634ae8e4df699b2"
                                                    + "d3b52af4df616ca8003502e38b81bfa6801148c7bab1870a694b44d82ff0"
                                                    + "98633edb09bfbab52b3e7498ce1826813da010000f7c458877f859f46442"
                                                    + "0853220d632d9d1fc113e885e631f15dfcf1fddba90c0c5aa520bc6a55a5"
                                                    + "6a1b29ead5492f83fe7e6b9494afbe16615daa446c2909c218dcd750ae4a"
                                                    + "9a9c69c74d748e904ba8e2ce2812d1ce3c4ed12fd82cca7fe81f88823907"
                                                    + "6702656ef1d3f93e472aae509a0ae5e241c4fd9b661f4cc6ffb02d416a72"
                                                    + "5469e51e27204b3db3f28961e244a9e6c3",
                                            16))),
                    new SshPublicKey<>(
                            PublicKeyFormat.ECDSA_SHA2_NISTP256,
                            new CustomEcPublicKey(
                                    PointFormatter.formatFromByteArray(
                                            NamedEcGroup.SECP256R1,
                                            ArrayConverter.hexStringToByteArray(
                                                    "045da168bd8be95222a7525588730d9fd223802f9ab084c8ab"
                                                            + "823dcc95bdbee003806f8dfd41a36ab5e2e36f25171a5c0c"
                                                            + "baf448d97ea8eb8d08a70274175f650d")),
                                    NamedEcGroup.SECP256R1),
                            new CustomEcPrivateKey(
                                    new BigInteger(
                                            "3412ac07c0f355f52df063d6e1464d0c9624c5d6c1e0fc14"
                                                    + "d1a6a8b79955f8cb",
                                            16),
                                    NamedEcGroup.SECP256R1)),
                    new SshPublicKey<>(
                            PublicKeyFormat.SSH_ED25519,
                            new XCurveEcPublicKey(
                                    ArrayConverter.hexStringToByteArray(
                                            "99AF546D30DD1770CC27A1A1CE7AD1CEC729823527529352141E89F7F3420F2C"),
                                    NamedEcGroup.CURVE25519),
                            new XCurveEcPrivateKey(
                                    ArrayConverter.hexStringToByteArray(
                                            "6D3703876ED02075102F767E2EA969E311B7776F71630B7C1DF3E55C98D6641B"),
                                    NamedEcGroup.CURVE25519)),
                    new SshPublicKey<>(
                            PublicKeyFormat.SSH_DSS,
                            new CustomDsaPublicKey(
                                    new BigInteger(
                                            "00D34ED25D35236E5A3EFCAE34C30F06F444D1FBE85DC29D71DAD5"
                                                    + "A8EFD5ED45609F4E29484DF5E21DB9926664296EF910AA9822FECDD"
                                                    + "97514479DC28C69AB424A12D792E3B38D56C2DE668DA788286E5136"
                                                    + "8AC1B837C7C928B5B5A6A277ECEA9436FAF7CBF279CD103695B7AEC"
                                                    + "96B4EF975A218483BB715FE0CFEE7BE9E07DFA5",
                                            16),
                                    new BigInteger(
                                            "00D8F3DAC6BFAA2CEAFCBF0E249DD0750913A5BFE9", 16),
                                    new BigInteger(
                                            "42B4D9C983941ADFDA0E6D9C4583F6FA96417017B389D750CFD717C"
                                                    + "591FD12931167D12C96E3345E79B6225360485FF2E839CA9C38"
                                                    + "D443A4AE2F13D6593FF69605866AC4AD1CD677441FD0D6ED15F"
                                                    + "F636D8231130CC07B8AA6F1DF54A6517983695E3E5FFA3BFF9A"
                                                    + "30B44423D8504CF0748AF99CA79B6A8599759E7C6DBBB5DC",
                                            16),
                                    new BigInteger(
                                            "68801435B2A260F778520BD23C9EBF38AF523CB81D64C56F8741890B"
                                                    + "1206CA2E175EE94BFF2C84601F357FB5B6071AB2240D7258D1EDE3D8B"
                                                    + "CC2F6E78DEA5DCBB5BC315B858A1DD833607E0433CDE2FD24240DD2D1"
                                                    + "C45F9508FBA25DC8E6F40D9BC58B6D3246865027E9B5E48F410E084B5"
                                                    + "2A1AE99D2966543243764436757F6",
                                            16)),
                            new CustomDsaPrivateKey(
                                    new BigInteger(
                                            "00D34ED25D35236E5A3EFCAE34C30F06F444D1FBE85DC29D71DAD5A8EFD5"
                                                    + "ED45609F4E29484DF5E21DB9926664296EF910AA9822FECDD97514479D"
                                                    + "C28C69AB424A12D792E3B38D56C2DE668DA788286E51368AC1B837C7C9"
                                                    + "28B5B5A6A277ECEA9436FAF7CBF279CD103695B7AEC96B4EF975A21848"
                                                    + "3BB715FE0CFEE7BE9E07DFA5",
                                            16),
                                    new BigInteger(
                                            "00D8F3DAC6BFAA2CEAFCBF0E249DD0750913A5BFE9", 16),
                                    new BigInteger(
                                            "42B4D9C983941ADFDA0E6D9C4583F6FA96417017B389D750CFD717C591FD"
                                                    + "12931167D12C96E3345E79B6225360485FF2E839CA9C38D443A4AE2F13D6"
                                                    + "593FF69605866AC4AD1CD677441FD0D6ED15FF636D8231130CC07B8AA6F1"
                                                    + "DF54A6517983695E3E5FFA3BFF9A30B44423D8504CF0748AF99CA79B6A85"
                                                    + "99759E7C6DBBB5DC",
                                            16),
                                    new BigInteger(
                                            "6616556442F6B8F1EA8B5FA3A93BB638D55737D8", 16))));

    InputStream id_rsa = KeyParser.class.getClassLoader().getResourceAsStream("keys/id_rsa-new1");

    InputStream id_dsa = KeyParser.class.getClassLoader().getResourceAsStream("keys/id_dsa");

    InputStream id_ecdsa = KeyParser.class.getClassLoader().getResourceAsStream("keys/id_ecdsa");

    InputStream id_ed25519 =
            KeyParser.class.getClassLoader().getResourceAsStream("keys/id_ed25519");

    @Test
    public void testRsaKeyParsing() {
        SshPublicKey rsaKey;
        rsaKey = KeyParser.readKeyPairFromBytes("keys/id_rsa");
        SshPublicKey check = userKeys.get(0);
        assertTrue(check.equals(rsaKey));
        assertEquals(rsaKey, userKeys.get(0));
    }

    @Test
    public void testDsaKeyParsing() {
        SshPublicKey dsaKey = null;
        dsaKey = KeyParser.readKeyPairFromBytes("keys/id_dsa");
        assertEquals(dsaKey, userKeys.get(3));
    }

    @Test
    public void testEcdsaKeyParsing() {
        SshPublicKey ecdsaKey;
        ecdsaKey = KeyParser.readKeyPairFromBytes("keys/id_ecdsa");

        assertTrue(ecdsaKey.equals(userKeys.get(1)));
    }

    @Test
    public void testEd25519KeyParsing() {
        SshPublicKey ed25519Key;
        ed25519Key = KeyParser.readKeyPairFromBytes("keys/id_ed25519");

        assertEquals(ed25519Key, userKeys.get(2));
    }
}
