package de.rub.nds.sshattacker.core.util;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;

import java.math.BigInteger;
import java.util.Arrays;

public class RsaPublicKey {
    private ModifiableBigInteger n;
    private ModifiableBigInteger e;


    public RsaPublicKey() {
    }

    public ModifiableBigInteger getN() {
        return n;
    }

    public void setN(byte[] nBytes) {
        BigInteger nNew = new BigInteger(Arrays.toString(nBytes), 16);
        this.n = ModifiableVariableFactory.safelySetValue(this.n, nNew);
    }

    public void setN(BigInteger n) {
        this.n = ModifiableVariableFactory.safelySetValue(this.n, n);
    }

    public ModifiableBigInteger getE() {
        return e;
    }

    public void setE(byte[] eBytes) {
        BigInteger eNew = new BigInteger(Arrays.toString(eBytes), 16);
        this.e = ModifiableVariableFactory.safelySetValue(this.e, eNew);
    }

    public void setE(BigInteger e) {
        this.e = ModifiableVariableFactory.safelySetValue(this.e, e);
    }
}
