package de.rub.nds.sshattacker.crypto;
import de.rub.nds.sshattacker.constants.CryptoConstants;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;

public class KeyDerivation {
    
    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] DheX25519(byte[] secretKey, byte[] publicKey){
        byte[] sharedKey = new byte[CryptoConstants.X25519_POINT_SIZE];
        X25519.precompute();
        X25519.scalarMult(secretKey, 0, publicKey, 0, sharedKey, 0);
        return sharedKey;
    }
    
    public static byte[] computeExchangeHash(byte[] input, MessageDigest md){
        return md.digest(input);
    }
    
//    public static byte[] deriveKey(byte[] sharedKey, byte[] exchangeHash, byte use, byte[] sessionID, int outputLen, String hashFunction){
//        try{
//        MessageDigest md = MessageDigest.getInstance(hashFunction);
//        }
//        catch (NoSuchAlgorithmException e){
//            LOGGER.error("Provider does not support this hashFunction:" + e.getMessage());
//        }
//        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
//        
//        try{
//        outStream.write(md.digest(Arrays.concatenate(sharedKey, exchangeHash, new byte[] {use}, sessionID)));
//        }
//        catch (IOException e){
//            LOGGER.error("Error while writing to outStream: " + e.getMessage());
//        }
//        
//        while(outStream.size()<outputLen){
//            try{
//            outStream.write(md.digest(Arrays.concatenate(sharedKey, exchangeHash, outStream.toByteArray())));
//            }
//            catch (IOException e){
//                LOGGER.error("Error while writing to outStream: " + e.getMessage());
//            }
//        }
//        return outStream.toByteArray();
//    }
}
