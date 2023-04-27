/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

import java.math.BigInteger;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

public final class Encoding {

    public static ArrayList<Integer> decode(List<Integer> s, List<Integer> m) {
        ArrayList<Integer> r = new ArrayList<>();
        if (m.size() == 0) {
            return r;
        }

        if (m.size() == 1) {
            r.add(
                    Math.floorMod(
                            IntStream.range(0, s.size())
                                    .mapToLong(i -> (long) (s.get(i) * Math.pow(256, i)))
                                    .sum(),
                            m.get(0).intValue()));
            return r;
        }

        int kLocal = 0;
        ArrayList<AbstractMap.SimpleEntry<Integer, Integer>> bottom = new ArrayList<>();
        ArrayList<Integer> m2 = new ArrayList<>();
        ArrayList<Integer> r2 = new ArrayList<>();
        int mLocal, rLocal, tLocal;
        int limit = 16384;

        for (int i = 0; i < m.size() - 1; i += 2) {
            mLocal = m.get(i) * m.get(i + 1);
            rLocal = 0;
            tLocal = 1;
            while (mLocal >= limit) {
                rLocal += s.get(kLocal) * tLocal;
                tLocal = tLocal * 256;
                kLocal += 1;
                mLocal = (mLocal + 255) / 256;
            }
            bottom.add(new AbstractMap.SimpleEntry<>(rLocal, tLocal));
            m2.add(mLocal);
        }

        if ((m.size() & 1) == 1) {
            m2.add(m.get(m.size() - 1));
        }

        r2 = decode(s.subList(kLocal, s.size()), m2);
        for (int i = 0; i < m.size() - 1; i += 2) {
            rLocal = bottom.get(i / 2).getKey();
            tLocal = bottom.get(i / 2).getValue();
            rLocal += tLocal * r2.get(i / 2);
            r.add(Math.floorMod(rLocal, m.get(i)));
            r.add(Math.floorMod(rLocal / m.get(i), m.get(i + 1)));
        }

        if ((m.size() & 1) == 1) {
            r.add(r2.get(r2.size() - 1));
        }
        return r;
    }

    public static ArrayList<Integer> encode(ArrayList<Integer> r, ArrayList<Integer> m) {
        ArrayList<Integer> s = new ArrayList<>();
        int mLocal, rLocal;
        int limit = 16384;

        if (m.size() == 0) {
            return s;
        }

        if (m.size() == 1) {
            mLocal = m.get(0);
            rLocal = r.get(0);
            while (mLocal > 1) {
                s.add(Math.floorMod(rLocal, 256));
                rLocal = rLocal / 256;
                mLocal = (mLocal + 255) / 256;
            }
            return s;
        }

        ArrayList<Integer> r2 = new ArrayList<>();
        ArrayList<Integer> m2 = new ArrayList<>();

        for (int i = 0; i < m.size() - 1; i += 2) {
            mLocal = m.get(i) * m.get(i + 1);
            rLocal = r.get(i) + m.get(i) * r.get(i + 1);
            while (mLocal >= limit) {
                s.add(Math.floorMod(rLocal, 256));
                rLocal = rLocal / 256;
                mLocal = (mLocal + 255) / 256;
            }
            r2.add(rLocal);
            m2.add(mLocal);
        }

        if ((m.size() & 1) == 1) {
            r2.add(r.get(r.size() - 1));
            m2.add(m.get(m.size() - 1));
        }
        s.addAll(encode(r2, m2));
        return s;
    }

    public static byte[] seq2byte(ArrayList<Integer> u, int radix, int batch, int bytes) {
        byte[] res = new byte[0];
        for (int i = 0; i < u.size(); i += batch) {
            BigInteger tmp = BigInteger.ZERO;
            for (int j = 0; j < batch; j++) {
                tmp =
                        tmp.add(
                                BigInteger.valueOf(u.get(i + j))
                                        .multiply(BigInteger.valueOf(radix).pow(j)));
            }
            res = ArrayConverter.concatenate(res, int2byte(tmp, bytes));
        }
        return res;
    }

    public static byte[] int2byte(BigInteger u, int bytes) {
        byte[] res = new byte[bytes];
        for (int i = 0; i < bytes; i++) {
            res[i] =
                    (byte)
                            ((u.divide(BigInteger.valueOf((long) (Math.pow(256, i))))
                                            .mod(BigInteger.valueOf(256)))
                                    .intValue());
        }
        return res;
    }

    public static long byte2int(byte[] s) {
        long res = 0;
        for (int i = 0; i < s.length; i++) {
            res += Math.round((s[i] & 0xff) * Math.pow(256, i));
        }
        return res;
    }

    public static ArrayList<BigInteger> byte2seq(byte[] s, int radix, int batch, int bytes) {
        long[] u = new long[(int) (Math.ceil(s.length / (double) bytes))];
        ArrayList<BigInteger> res = new ArrayList<>();
        int k = 0;
        for (int i = 0; i < s.length; i += bytes) {
            u[k] = byte2int(Arrays.copyOfRange(s, i, i + bytes));
            k++;
        }
        for (int i = 0; i < u.length; i++) {
            for (int j = 0; j < batch; j++) {
                res.add(
                        BigInteger.valueOf(u[i])
                                .divide(BigInteger.valueOf(radix).pow(j))
                                .mod(BigInteger.valueOf(radix)));
            }
        }
        return res;
    }
}
