package dev.yuizho.login_demo.scratch.webauthn;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * authenticatorData のバイト列を解析したもの
 * <pre>
 * rpIdHash(32) | flags(1) | signCount(4) | [AT フラグがあれば] aaguid(16) | credentialIdLength(2) | credentialId | 公開鍵(COSE)
 * </pre>
 * ログイン時は AT フラグが立たないので、aaguid 以降は null になる。
 */
record AuthenticatorData(byte[] rpIdHash, int flags, long signCount,
                         byte[] aaguid, byte[] credentialId, byte[] credentialPublicKey) {
    static final int UP = 0x01; // ユーザーの存在確認 (タッチなど)
    static final int UV = 0x04; // ユーザー確認 (生体認証・PIN など)
    static final int AT = 0x40; // 資格情報データ (aaguid, credentialId, 公開鍵) あり

    static AuthenticatorData parse(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes); // ビッグエンディアン
        byte[] rpIdHash = new byte[32];
        buffer.get(rpIdHash);
        int flags = buffer.get() & 0xff;
        long signCount = buffer.getInt() & 0xffffffffL;
        if ((flags & AT) == 0) {
            return new AuthenticatorData(rpIdHash, flags, signCount, null, null, null);
        }

        byte[] aaguid = new byte[16];
        buffer.get(aaguid);
        byte[] credentialId = new byte[buffer.getShort() & 0xffff];
        buffer.get(credentialId);

        // 公開鍵は長さが書かれていないので、CBOR として1つ読んで終わりの位置を知る
        int start = buffer.position();
        Cbor cbor = new Cbor(bytes, start);
        cbor.read();
        byte[] credentialPublicKey = Arrays.copyOfRange(bytes, start, cbor.position());
        return new AuthenticatorData(rpIdHash, flags, signCount, aaguid, credentialId, credentialPublicKey);
    }

    boolean has(int flag) {
        return (flags & flag) != 0;
    }
}
