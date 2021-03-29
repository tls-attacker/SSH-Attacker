/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.layers;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.state.SshContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CryptoLayer {

    private final SshContext context;

    private static final Logger LOGGER = LogManager.getLogger();

    private Cipher encryption;
    private Cipher decryption;

    private Mac mac;
    @SuppressWarnings("FieldCanBeLocal")
    private Mac verify;

    public CryptoLayer(SshContext context) {
        this.context = context;
    }

    /**
     * Can only be called after keys have been derived
     */
    public void init() {
        initCiphers();
        initMacs();
    }

    private void initCiphers() {
        try {
            encryption = Cipher.getInstance("AES/CBC/NoPadding");
            Key encryptionKey = new SecretKeySpec(context.getEncryptionKeyClientToServer(), "AES");
            IvParameterSpec encryptionIV = new IvParameterSpec(context.getInitialIvClientToServer());
            encryption.init(Cipher.ENCRYPT_MODE, encryptionKey, encryptionIV);

            decryption = Cipher.getInstance("AES/CBC/NoPadding");
            Key decryptionKey = new SecretKeySpec(context.getEncryptionKeyServerToClient(), "AES");
            IvParameterSpec decryptionIV = new IvParameterSpec(context.getInitialIvServerToClient());
            decryption.init(Cipher.DECRYPT_MODE, decryptionKey, decryptionIV);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Provider does not support this algorithm. " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            LOGGER.warn("Provider does not support this padding. " + e.getMessage());
        } catch (InvalidKeyException e) {
            LOGGER.warn("Keys does not correspond to used cipher. " + e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.warn(e.getMessage());
        }
    }

    private void initMacs() {
        try {
            mac = Mac.getInstance("HMacSHA1");
            Key macKey = new SecretKeySpec(context.getIntegrityKeyClientToServer(), "HMac-SHA1");
            mac.init(macKey);

            verify = Mac.getInstance("HMacSHA1");
            Key verifyKey = new SecretKeySpec(context.getIntegrityKeyServerToClient(), "HMac-SHA1");
            verify.init(verifyKey);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("HMac is not supported. " + e.getMessage());
        } catch (InvalidKeyException e) {
            LOGGER.warn("Key is not suitable for this Mac. " + e.getMessage());
        }
    }

    // TODO only supports aes-128-cbc, hmac-sha1
    public byte[] decrypt(byte[] raw) {
        if (decryption == null) {
            return decrypt_temp(raw);
        }
        return decryption.update(raw);
    }

    public byte[] decrypt_temp(byte[] raw) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] key = new byte[32];
            byte[] iv = new byte[32];
            random.nextBytes(key);
            random.nextBytes(iv);
            Cipher temp = Cipher.getInstance("AES/CBC/NoPadding");
            Key encryptionKey = new SecretKeySpec(key, "AES");
            IvParameterSpec encryptionIV = new IvParameterSpec(iv);
            temp.init(Cipher.DECRYPT_MODE, encryptionKey, encryptionIV);
            return temp.update(raw);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            java.util.logging.Logger.getLogger(CryptoLayer.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new byte[0];
    }

    public byte[] encrypt_temp(byte[] raw) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] key = new byte[32];
            byte[] iv = new byte[32];
            random.nextBytes(key);
            random.nextBytes(iv);
            Cipher temp = Cipher.getInstance("AES/CBC/NoPadding");
            Key encryptionKey = new SecretKeySpec(key, "AES");
            IvParameterSpec encryptionIV = new IvParameterSpec(iv);
            temp.init(Cipher.ENCRYPT_MODE, encryptionKey, encryptionIV);
            return temp.update(raw);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            java.util.logging.Logger.getLogger(CryptoLayer.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new byte[0];
    }

    public byte[] encrypt(byte[] raw) {
        if (encryption == null) {
            return encrypt_temp(raw);
        }
        return encryption.update(raw);
    }

    // mac = MAC(key, sequence_number || unencrypted_packet)
    public byte[] computeMac(byte[] raw) {
        byte[] byteSequenceNumber = ArrayConverter.intToBytes(context.getSequenceNumber(), 4);
        byte[] toMac = ArrayConverter.concatenate(byteSequenceNumber, raw);
        return mac.doFinal(toMac);
    }

    public byte[] macAndEncrypt(byte[] packet) {
        if (context.isIsEncryptionActive()) {
            return ArrayConverter.concatenate(encrypt(packet), computeMac(packet));
        } else {
            return packet;
        }
    }

    public byte[] decryptBinaryPacket(byte[] raw) {
        byte[] firstBlock = Arrays.copyOfRange(raw, 0, context.getCipherAlgorithmServerToClient().getBlockSize());

        byte[] decryptedFirstBlock = decrypt(firstBlock);
        int packetLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(decryptedFirstBlock, 0,
                DataFormatConstants.INT32_SIZE));

        int macStart = BinaryPacketConstants.LENGTH_FIELD_LENGTH + packetLength;
        int macEnd = macStart + context.getMacAlgorithmServerToClient().getOutputSize();
        byte[] macced = Arrays.copyOfRange(raw, macStart, macEnd);
        byte[] toDecrypt = Arrays.copyOfRange(raw, context.getCipherAlgorithmServerToClient().getBlockSize(), macStart);
        byte[] decrypted = decrypt(toDecrypt);
        return ArrayConverter.concatenate(decryptedFirstBlock, decrypted, macced);
    }

    public byte[] decryptBinaryPackets(byte[] toDecrypt) {
        if (context.isIsEncryptionActive()) {
            byte[] completeDecrypted = new byte[0];

            while (toDecrypt.length >= context.getCipherAlgorithmServerToClient().getBlockSize()
                    + context.getMacAlgorithmServerToClient().getOutputSize()) {
                byte[] decrypted = decryptBinaryPacket(toDecrypt);
                completeDecrypted = ArrayConverter.concatenate(completeDecrypted, decrypted);
                toDecrypt = Arrays.copyOfRange(toDecrypt, decrypted.length, toDecrypt.length);
            }
            return completeDecrypted;
        } else {
            return toDecrypt;
        }
    }
}
