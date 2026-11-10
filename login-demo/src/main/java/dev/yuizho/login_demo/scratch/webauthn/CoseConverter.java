package dev.yuizho.login_demo.scratch.webauthn;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Map;

import static dev.yuizho.login_demo.scratch.webauthn.ScratchVerifier.check;

/**
 * COSE 形式の公開鍵 (RFC 9053) を Java の PublicKey に変換する (ES256 のみ)
 * <pre>
 * { 1(kty): 2(EC2), 3(alg): -7(ES256), -1(crv): 1(P-256), -2(x): 32バイト, -3(y): 32バイト }
 * </pre>
 */
final class CoseConverter {
    private CoseConverter() {
    }

    static PublicKey toPublicKey(byte[] cose) {
        Map<?, ?> map = (Map<?, ?>) Cbor.decode(cose);
        check(Long.valueOf(2).equals(map.get(1L)), "kty が EC2 ではない: " + map.get(1L));
        check(Long.valueOf(-7).equals(map.get(3L)), "alg が ES256 ではない: " + map.get(3L));
        check(Long.valueOf(1).equals(map.get(-1L)), "crv が P-256 ではない: " + map.get(-1L));
        BigInteger x = new BigInteger(1, (byte[]) map.get(-2L));
        BigInteger y = new BigInteger(1, (byte[]) map.get(-3L));
        try {
            // 曲線 P-256 (secp256r1) 上の点 (x, y) が公開鍵
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), curve));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("公開鍵に変換できない", e);
        }
    }
}
