package de.rub.nds.sshattacker.core.util;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parser class to parse an RSA public key in ssh-rsa format (see RFC4253 Section 6.6)
 */
public class RsaPublicKeyParser extends Parser<RsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public RsaPublicKey parse() {
        RsaPublicKey publicKey = new RsaPublicKey();
        int keytypeLength = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        String keytype = parseByteString(keytypeLength);

        if(!keytype.equals("ssh-rsa")) {
            LOGGER.debug("Tried to parse key as rsa key, but type was: " + keytype);
        }

        int eLength = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("Exponent length: " + eLength);
        publicKey.setE(parseBigIntField(eLength));
        LOGGER.debug("Exponent: " + publicKey.getE().getValue());

        int nLength = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("Modulus length: " + nLength);
        publicKey.setN(parseBigIntField(nLength));
        LOGGER.debug("Modulus: " + publicKey.getN().getValue());

        return publicKey;
    }
}
