package de.rub.nds.sshattacker.protocol.layers;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.state.SshContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CryptoLayer {

    private SshContext context;
    
    private static final Logger LOGGER = LogManager.getLogger();
        
    private Cipher encryption;
    private Cipher decryption;
    
    private Mac mac;
    private Mac verify;
    
    public CryptoLayer(SshContext context){
        this.context = context;
    }
    
    public void init(){
        initCiphers();
        initMacs();
    }
    
    private void initCiphers(){
        try{
        encryption = Cipher.getInstance("AES/CBC/NoPadding");
        Key encryptionKey = new SecretKeySpec(context.getEncryptionKeyClientToServer(), "AES");
        IvParameterSpec encryptionIV = new IvParameterSpec(context.getInitialIvClientToServer());
        encryption.init(Cipher.ENCRYPT_MODE, encryptionKey, encryptionIV);
        
        decryption = Cipher.getInstance("AES/CBC/NoPadding");
        Key decryptionKey = new SecretKeySpec(context.getEncryptionKeyServerToClient(), "AES");
        IvParameterSpec decryptionIV = new IvParameterSpec(context.getInitialIvServerToClient());
        decryption.init(Cipher.DECRYPT_MODE, decryptionKey, decryptionIV);
        }
        catch (NoSuchAlgorithmException e){
            LOGGER.warn("Provider does not support this algorithm. " + e.getMessage());
        }
        catch (NoSuchPaddingException e){
            LOGGER.warn("Provider does not support this padding. " + e.getMessage());
        }
        catch (InvalidKeyException e){
            LOGGER.warn("Keys does not correspond to used cipher. " + e.getMessage());
        }
        catch (InvalidAlgorithmParameterException e){
            LOGGER.warn(e.getMessage());
        }
    }
    
    private void initMacs(){
        try{
        mac = Mac.getInstance("HMacSHA1");
        Key macKey = new SecretKeySpec(context.getIntegrityKeyClientToServer(), "HMac-SHA1");
        mac.init(macKey);
        
        verify = Mac.getInstance("HMacSHA1");
        Key verifyKey = new SecretKeySpec(context.getIntegrityKeyServerToClient(), "HMac-SHA1");
        verify.init(verifyKey);
        }
        catch (NoSuchAlgorithmException e){
            LOGGER.warn("HMac is not supported. " + e.getMessage());
        }
        catch (InvalidKeyException e){
            LOGGER.warn("Key is not suitable for this Mac. " + e.getMessage());
        }
    }
    
    // TODO only supports aes-128-cbc, hmac-sha1
    public byte[] decryptBinaryPacket(byte[] raw){
        byte[] result = decryption.update(raw);
        return result;
    }
    
    public byte[] encryptBinaryPacket(byte[] raw){
        byte[] result = encryption.update(raw);
        return result;
    }
    
    // mac = MAC(key, sequence_number || unencrypted_packet)
    public byte[] computeMac(byte[] raw){
        byte[] byteSequenceNumber = ArrayConverter.intToBytes(context.getSequenceNumber(), 4);
        byte[] toMac = ArrayConverter.concatenate(byteSequenceNumber, raw);
        return mac.doFinal(toMac);
    }
    
    public byte[] macAndEncrypt(byte[] packet){
        if (context.isIsEncryptionActive()){
            return ArrayConverter.concatenate(encryptBinaryPacket(packet),
                    computeMac(packet));
        }
        else{
            return packet;
        }
    }
    
    public byte[] decryptAndCopyMac(byte[] raw){
        if (context.isIsEncryptionActive()){
            int macStart = raw.length-context.getMacAlgorithmClientToServer().getOutputSize();
            byte[] macced = Arrays.copyOfRange(raw, macStart, raw.length);
            byte[] toDecrypt = Arrays.copyOfRange(raw, 0, macStart);
            byte[] decrypted = decryptBinaryPacket(toDecrypt);
            byte[] result = ArrayConverter.concatenate(decrypted, macced);
            return result;
        }
        else{
            return raw;
        }
    }
}
