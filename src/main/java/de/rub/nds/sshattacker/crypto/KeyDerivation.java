package de.rub.nds.sshattacker.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.CryptoConstants;
import de.rub.nds.sshattacker.util.Converter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;

public class KeyDerivation {

    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] DheX25519(byte[] secretKey, byte[] publicKey) {
        byte[] sharedKey = new byte[CryptoConstants.X25519_POINT_SIZE];
        X25519.precompute();
        X25519.scalarMult(secretKey, 0, publicKey, 0, sharedKey, 0);
        return sharedKey;
    }

    public static byte[] computeExchangeHash(byte[] input, String hashAlgorithm){
        System.out.println(ArrayConverter.bytesToRawHexString(input));
        try{
             Files.write(Paths.get("/home/spotz/git/sshlab/kex.javadump"),
                    java.util.Arrays.asList(ArrayConverter.bytesToRawHexString(input)));
        }
        catch (IOException e){
            System.out.println(e.getMessage());
        }
        return getMessageDigestInstance(hashAlgorithm).digest(input);
    }
    
    public static byte[] computeExchangeHash(String clientVersion, 
            String serverVersion, String clientInitMessage, 
            String serverInitMessage, String hostKey, String clientKeyShare,
            String serverKeyShare, byte[] sharedSecret, String hashFunction) {
        byte[] clientVersionConverted = Converter.stringToLengthPrefixedString(clientVersion);
        byte[] serverVersionConverted = Converter.stringToLengthPrefixedString(serverVersion);
        byte[] clientInitMessageConverted = Converter.stringToLengthPrefixedString(clientInitMessage);
        byte[] serverInitMessageConverted = Converter.stringToLengthPrefixedString(serverInitMessage);
        byte[] hostKeyConverted = Converter.stringToLengthPrefixedString(hostKey);
        byte[] clientKeyShareConverted = Converter.stringToLengthPrefixedString(clientKeyShare);
        byte[] serverKeyShareConverted = Converter.stringToLengthPrefixedString(serverKeyShare);
        byte[] keyShareConverted = Converter.byteArraytoMpint(sharedSecret);
        byte[] input = Converter.concatenate(clientVersionConverted, serverVersionConverted, clientInitMessageConverted, serverInitMessageConverted, hostKeyConverted, clientKeyShareConverted, serverKeyShareConverted, keyShareConverted);
        System.out.println(ArrayConverter.bytesToRawHexString(input));
       
        return getMessageDigestInstance(hashFunction).digest(input);
    }
    
    public static MessageDigest getMessageDigestInstance(String hashFunction) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(hashFunction);

        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Provider does not support this hashFunction:" + e.getMessage());
        }
        return md;
    }

    public static byte[] deriveKey(byte[] sharedKey, byte[] exchangeHash, byte use, byte[] sessionID, int outputLen, String hashFunction) {
        byte[] sharedKeyMpint = Converter.byteArraytoMpint(sharedKey);
        try {
            MessageDigest md = MessageDigest.getInstance(hashFunction);
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();

            outStream.write(md.digest(Arrays.concatenate(sharedKeyMpint, exchangeHash, new byte[]{use}, sessionID)));
            
            while (outStream.size() < outputLen) {
                outStream.write(md.digest(Arrays.concatenate(sharedKeyMpint, exchangeHash, outStream.toByteArray())));
            }
            return Arrays.copyOfRange(outStream.toByteArray(), 0, outputLen);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Provider does not support this hashFunction:" + e.getMessage());
            return new byte[0];
        } catch (IOException e){
            LOGGER.error("Error while writing: " + e.getMessage());
            return new byte[0];
        }
    }
}