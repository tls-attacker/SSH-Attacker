package de.rub.nds.sshattacker.util;

public class Util {

    public static String getDigestAlgorithmFromKeyExchange(String kexAlgorithm) {
        // TODO not clean, works for now
        if (kexAlgorithm.contains("256")) {
            return "SHA-256";
        } else if (kexAlgorithm.contains("384")) {
            return "SHA-384";
        } else if (kexAlgorithm.contains("512")) {
            return "SHA-512";
        } else if (kexAlgorithm.contains("sha1")) {
            return "SHA-1";
        }
        return "SHA-256";
    }

}
