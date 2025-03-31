const A = "zKMTNa/piUlaWk17gdf84QpnNDA2lDEuJ2BpAxlzT029+zn5k55nkLOKGkoi6XzrLI4UaCv7DhC4fYhA9f0inC0s8Nk22okLJXhjSXOjHzuvmZwqBRN1l9wFiPuYIDfPWUtZfBzj0E0cCeN1DI+whTQfwdsNCTFlmj9C8hRUTZBE8sy7RDbwnIU=";
const S = document.getElementById("search");
const Z = document.getElementById("search-text");

function compress(plainTextArray) {
    try {
        return pako.deflate(plainTextArray);
    } catch (e) {
        console.error("Compression error:", e);
        return null;
    }
}

function decompress(compressedArray) {
    try {
        return pako.inflate(compressedArray);
    } catch (e) {
        console.error("Decompression error:", e);
        return null;
    }
}

async function decrypt(encryptedData, password=null, compressed=false) {
    try {
        const base32 = Uint8Array.from(atob(password ? password : A), c => c.charCodeAt(0));
        const iv = base32.slice(0, 16);
        const salt = base32.slice(16, 28);
        const encryptedCompressedText = base32.slice(28, 44);
        const tag = base32.slice(44);
        
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(encryptedData),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
        
        const encryptedKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: iv,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );
        
        const decryptedKey = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: salt, tagLength: 128 },
            encryptedKey,
            new Uint8Array([...tag, ...encryptedCompressedText])
        );
        
        return new TextDecoder().decode(compressed ? decompress(new Uint8Array(decryptedKey)) : decryptedKey);
    } catch (e) {
        console.warn("Decryption failed: Invalid password or corrupted data.", e);
        return null;
    }
}

async function encrypt(plaintext, password, compresss=false) {
    const encoder = new TextEncoder();
    const encryptedData = encoder.encode(password);
    const salt = crypto.getRandomValues(new Uint8Array(16));

    const key = await crypto.subtle.importKey(
        "raw", 
        encryptedData,
        { name: "PBKDF2" }, 
        false, 
        ["deriveBits", "deriveKey"]
    );
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        key,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = encoder.encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
            tagLength: 128
        },
        derivedKey,
        compresss ? compress(encoded) : encoded
    );
    const cipherArray = new Uint8Array(ciphertext);
    const tag = cipherArray.slice(-16);
    const e = new Uint8Array(salt.length + iv.length + tag.length + cipherArray.length - 16);
    e.set(salt);
    e.set(iv, salt.length);
    e.set(tag, salt.length + iv.length);
    e.set(cipherArray.slice(0, cipherArray.length - 16), salt.length + iv.length + tag.length);
    return btoa(String.fromCharCode(...e));
}

S.addEventListener("input", _ => {
    Z.innerText = S.value ? "SEARCH FOR \"" + S.value.toUpperCase() + "\"" : "";
});
