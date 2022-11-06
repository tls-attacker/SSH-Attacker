/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import java.util.Arrays;
import java.util.Optional;

public class SntrupCore {
    private RQ h;
    private R3 gInv;
    private Short f;
    private RQ f3;
    private RQ f3Inv;
    private R g;
    private SntrupParameterSet set;

    public SntrupCore(SntrupParameterSet set) {
        this.set = set;
    }

    public SntrupKeyPairCore keyGenCore() {
        generateG();
        generateF();
        generateH();
        SntrupPubKeyCore pubK = new SntrupPubKeyCore(h);
        SntrupPrivKeyCore privK = new SntrupPrivKeyCore(f, f3, f3Inv, g, gInv);
        return new SntrupKeyPairCore(privK, pubK);
    }

    public Rounded encrypt(Short input, SntrupPubKeyCore pubK) {
        RQ hr = RQ.multiply(input, pubK.getH());
        return Rounded.round(hr);
    }

    public Short decrypt(Rounded ciphertext, SntrupPrivKeyCore privK) {
        RQ cf3 = RQ.multiply(ciphertext, privK.getF3());
        R3 e = new R3(cf3.getSet(), cf3.stream().toArray());
        R3 ev = R3.multiply(e, privK.getgInv());
        System.out.println(Arrays.toString(e.stream().toArray()));
        R r = R.lift(ev);

        return Short.createShort(set, r.stream().toArray());
    }

    private void generateG() {
        while (g == null) {
            R tmp = R.randomSmall(set);
            Optional<R3> tmpInv = R3.isInvertibleInR3(set, tmp);
            if (tmpInv.isPresent()) {
                g = tmp;
                gInv = tmpInv.get();
            }
        }
    }

    private void generateF() {
        f = Short.createRandomShort(set);
        f3 = RQ.multiply(3, f);
    }

    private void generateH() {
        f3 = RQ.multiply(3, f);
        f3Inv = RQ.invert(f3);
        h = RQ.multiply(g, f3Inv);
    }
}
