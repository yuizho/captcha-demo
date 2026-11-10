// 実験用: パスキー登録時の attestationObject をデコードしてコンソールに出す
// CBOR のデコードには cbor-x (グローバル変数 CBOR) を使う

async function logAttestationObject(credential) {
    // attestationObject は CBOR: { fmt, attStmt, authData }
    const attestationObject = CBOR.decode(new Uint8Array(credential.response.attestationObject));
    console.log("[attestation] fmt (attestation の形式)", attestationObject.fmt);
    console.log("[attestation] attStmt (attestation statement)", toObject(attestationObject.attStmt));

    // authData は決まったバイト位置で並んだバイト列
    const authData = new Uint8Array(attestationObject.authData);
    const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);

    const rpIdHash = authData.slice(0, 32);
    const expectedRpIdHash = new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(location.hostname)));
    console.log("[attestation] authData.rpIdHash", toHex(rpIdHash),
        `(SHA-256("${location.hostname}") と一致: ${toHex(rpIdHash) === toHex(expectedRpIdHash)})`);

    const flags = authData[32];
    console.log("[attestation] authData.flags", flags.toString(2).padStart(8, "0"), {
        UP_ユーザーの存在確認: !!(flags & 0x01),
        UV_ユーザー確認: !!(flags & 0x04),
        BE_バックアップ可能: !!(flags & 0x08),
        BS_バックアップ済み: !!(flags & 0x10),
        AT_資格情報データあり: !!(flags & 0x40),
        ED_拡張データあり: !!(flags & 0x80)
    });

    console.log("[attestation] authData.signCount", view.getUint32(33));

    if (!(flags & 0x40)) {
        return;
    }
    // AT フラグが立っていれば、続けて資格情報データ (aaguid, credentialId, 公開鍵) が入っている
    console.log("[attestation] authData.aaguid (認証器のモデルID)", toUuid(authData.slice(37, 53)));

    const credentialIdLength = view.getUint16(53);
    const credentialId = authData.slice(55, 55 + credentialIdLength);
    console.log("[attestation] authData.credentialId", toBase64Url(credentialId),
        `(credential.id と一致: ${toBase64Url(credentialId) === credential.id})`);

    // 公開鍵は COSE 形式の CBOR (ED フラグがあれば後ろに拡張データの CBOR が続く)
    const [coseKey] = CBOR.decodeMultiple(authData.slice(55 + credentialIdLength));
    const key = toObject(coseKey);
    console.log("[attestation] authData.credentialPublicKey (COSE)", {
        "1_kty (鍵の種類 2=EC2, 3=RSA, 1=OKP)": key[1],
        "3_alg (アルゴリズム -7=ES256, -257=RS256, -8=EdDSA)": key[3],
        "-1_crv (曲線 1=P-256)": key[-1],
        "-2_x": key[-2] && toHex(key[-2]),
        "-3_y": key[-3] && toHex(key[-3])
    });
}

// CBOR の map は Map でデコードされることがあるので、見やすいようにオブジェクトにする
function toObject(value) {
    return value instanceof Map ? Object.fromEntries(value) : value;
}

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function toUuid(bytes) {
    return toHex(bytes).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
}

function toBase64Url(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
