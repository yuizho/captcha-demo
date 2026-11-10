package dev.yuizho.login_demo.scratch.webauthn;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * WebAuthn で使う範囲だけ読める最小限の CBOR デコーダ (RFC 8949)
 * <p>
 * 1バイト目の上位3ビットが型 (major type)、下位5ビットが長さや値 (argument) を表す。
 * 浮動小数点・タグ・不定長には対応しない。
 */
final class Cbor {
    private final byte[] bytes;
    private int position;

    Cbor(byte[] bytes, int position) {
        this.bytes = bytes;
        this.position = position;
    }

    static Object decode(byte[] bytes) {
        return new Cbor(bytes, 0).read();
    }

    /** 次に読むバイト位置 (read() の後に呼ぶと、読んだ値の終わりがわかる) */
    int position() {
        return position;
    }

    Object read() {
        int initial = bytes[position++] & 0xff;
        int majorType = initial >> 5;
        long argument = readArgument(initial & 0x1f);
        return switch (majorType) {
            case 0 -> argument; // 符号なし整数
            case 1 -> -1 - argument; // 負の整数 (-1 - argument)
            case 2 -> readBytes((int) argument); // バイト列
            case 3 -> new String(readBytes((int) argument), StandardCharsets.UTF_8); // 文字列
            case 4 -> { // 配列 (argument = 要素数)
                List<Object> list = new ArrayList<>();
                for (long i = 0; i < argument; i++) {
                    list.add(read());
                }
                yield list;
            }
            case 5 -> { // マップ (argument = ペア数)
                Map<Object, Object> map = new LinkedHashMap<>();
                for (long i = 0; i < argument; i++) {
                    Object mapKey = read();
                    map.put(mapKey, read());
                }
                yield map;
            }
            case 7 -> switch ((int) argument) { // 単純値
                case 20 -> false;
                case 21 -> true;
                case 22 -> null;
                default -> throw new IllegalArgumentException("未対応の CBOR 単純値: " + argument);
            };
            default -> throw new IllegalArgumentException("未対応の CBOR major type: " + majorType);
        };
    }

    // 下位5ビットが 24 未満ならそれ自体が値、24〜27 なら続く 1/2/4/8 バイトが値
    private long readArgument(int additionalInfo) {
        if (additionalInfo < 24) {
            return additionalInfo;
        }
        int length = switch (additionalInfo) {
            case 24 -> 1;
            case 25 -> 2;
            case 26 -> 4;
            case 27 -> 8;
            default -> throw new IllegalArgumentException("未対応の CBOR additional info: " + additionalInfo);
        };
        long value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (bytes[position++] & 0xff);
        }
        return value;
    }

    private byte[] readBytes(int length) {
        byte[] result = Arrays.copyOfRange(bytes, position, position + length);
        position += length;
        return result;
    }
}
