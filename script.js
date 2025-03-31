// spicy!
const A = "zKMTNa/piUlaWk17gdf84QpnNDA2lDEuJ2BpAxlzT029+zn5k55nkLOKGkoi6XzrLI4UaCv7DhC4fYhA9f0inC0s8Nk22okLJXhjSXOjHzuvmZwqBRN1l9wFiPuYIDfPWUtZfBzj0E0cCeN1DI+whTQfwdsNCTFlmj9C8hRUTZBE8sy7RDbwnIU=";
const S = document.getElementById("search");
const Z = document.getElementById("search-text");
const C = document.getElementById("sbtn");
const E = document.getElementById("cbtn");
const V = document.getElementById("vbtn");
const L = document.getElementById("abtn");
const M = document.getElementById("menus");
const K = document.getElementById("search-menu");
const J = document.getElementById("admin-menu");
const G = document.getElementById("save-menu");
const P = document.getElementById("a");
const U = document.getElementById("al");
const F = document.getElementById("f");
const R = document.getElementById("content");
const N = document.getElementById("nas");
const Y = document.getElementById("save");
const O = document.getElementById("s");
const Q = []; // {name: "Text", parent: null/parent uuid4, id: uuid4, description: "Markdown text", position: number}
const W = [{title: "Test", category: null, content: "Test text", password: null, salt: null, key: null, iv: null, position: 1}]; // {title: "Text", category: null/category uuid4, content: "Markdown text", password: null/"password", salt: Uint8Array, key: CryptoKey, iv: Uint8Array, encrypted: true/null, position: number}

const MENUS = [[K, C], [J, L], [G, V]]

let a = null;
let b = true;
Y.ariaDisabled = !b;

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

async function baseEncrypt(encoded, salt, key, iv, compresss=false, raw=false) {
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
            tagLength: 128
        },
        key,
        compresss ? compress(encoded) : encoded
    );
    const cipherArray = new Uint8Array(ciphertext);
    const tag = cipherArray.slice(-16);
    const e = new Uint8Array(salt.length + iv.length + tag.length + cipherArray.length - 16);
    e.set(salt);
    e.set(iv, salt.length);
    e.set(tag, salt.length + iv.length);
    e.set(cipherArray.slice(0, cipherArray.length - 16), salt.length + iv.length + tag.length);
    return raw ? e : btoa(String.fromCharCode(...e));
}

async function encrypt(plaintext, password, compresss=false, raw=false) {
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
    return baseEncrypt(encoder.encode(plaintext), salt, derivedKey, iv, compresss, raw);
}

async function encodeAndEncrypt(content, password, salt, key, iv, encrypted) {
    let data = new TextEncoder().encode(content);

    if (!encrypted) {
        if (salt && key && iv) {
            data = await baseEncrypt(data, salt, key, iv, true, true);
        } else if (password) {
            data = await encrypt(content, password, true, true);
        }
    }

    return compress(data);
}

function buildCategoryStructure(Q) {
    const categories = {};
    Q.forEach(({ id, name, parent, description }) => {
        categories[id] = { name, parent, description, path: category.parent ? null : `data/${name}` };
    });
    Object.values(categories).forEach(category => {
        if (category.parent)
            category.path = `${categories[category.parent].path}/${category.name}`;
    });
    return categories;
}

async function processData(W, categories) {
    const files = {};
    for (const item of W) {
        const categoryPath = item.category ? categories[item.category]?.path : 'data';
        const filePath = `${categoryPath}/${item.title}.hyl`;
        files[filePath] = await encodeAndEncrypt(item.content, item.password, item.salt, item.key, item.iv, item.encrypted);
    }
    return files;
}

async function processCategories(categories) {
    const files = {};
    for (const id in categories) {
        const category = categories[id];
        const filePath = `${category.path}/.category`;
        const data = new TextEncoder().encode(category.description || '');
        files[filePath] = compress(data);
    }
    return files;
}

async function getLatestCommitSHA(repo) {
    const response = await fetch(`https://api.github.com/repos/${repo}/git/refs/heads/master`, {
        headers: { 'Authorization': `token ${a}` }
    });
    const data = await response.json();
    return data.object.sha;
}

async function getTree(repo, baseTreeSHA, files) {
    const tree = [];
    for (const path in files) {
        tree.push({
            path,
            mode: "100644",
            type: "blob",
            content: btoa(String.fromCharCode(...new Uint8Array(files[path])))
        });
    }
    const response = await fetch(`https://api.github.com/repos/${repo}/git/trees`, {
        method: 'POST',
        headers: { 'Authorization': `token ${a}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ base_tree: baseTreeSHA, tree })
    });
    const data = await response.json();
    return data.sha;
}

async function createCommit(repo, parentSHA, treeSHA) {
    const response = await fetch(`https://api.github.com/repos/${repo}/git/commits`, {
        method: 'POST',
        headers: { 'Authorization': `token ${a}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: O.value || "Update [no info provided]", tree: treeSHA, parents: [parentSHA] })
    });
    const data = await response.json();
    return data.sha;
}

async function updateBranch(repo, commitSHA) {
    await fetch(`https://api.github.com/repos/${repo}/git/refs/heads/master`, {
        method: 'PATCH',
        headers: { 'Authorization': `token ${a}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ sha: commitSHA })
    });
}

async function commitToGitHub(files, token) {
    const repo = 'alfuwu/Hyleus';
    const latestCommitSHA = await getLatestCommitSHA(repo, token);
    const treeSHA = await getTree(repo, token, latestCommitSHA, files);
    const commitSHA = await createCommit(repo, token, latestCommitSHA, treeSHA);
    await updateBranch(repo, token, commitSHA);
}

function opacitate(ele, startOpac, endOpac) {
    ele.animate([
        { opacity: startOpac },
        { opacity: endOpac }
    ], {
        duration: 200,
        fill: "forwards",
        easing: "ease-in-out"
    })
}

S.addEventListener("input", () => {
    Z.innerText = S.value ? "SEARCH FOR \"" + S.value.toUpperCase() + "\"" : "";
});

for (const m of MENUS)
    if (m[1] !== L)
        m[1].addEventListener("click", event => {
            if (event.button === 0) {
                M.classList.remove("hidden");
                F.classList.remove("h");
                m[0].classList.remove("hidden", "h");
                opacitate(F, 0, 0.5);
                opacitate(m[0], 0, 1);
            }
        });

L.addEventListener("click", event => {
    if (event.button === 0) {
        if (a !== null) {
            a = null;
            document.getElementsByName("adm").forEach(ele => ele.classList.add("hidden"));
            localStorage.removeItem("hyleus-admin");
        } else {
            M.classList.remove("hidden");
            F.classList.remove("h");
            J.classList.remove("hidden", 'h');
            opacitate(F, 0, 0.5);
            opacitate(J, 0, 1);
        }
    }
});

F.addEventListener("click", event => {
    if (event.button === 0)
        closeMenus();
})

function closeMenus() {
    opacitate(F, 0.5, 0);
    for (const m of MENUS)
        opacitate(m[0], 1, 0);
    setTimeout(() => {
        M.classList.add("hidden");
        F.classList.add("h");
        for (const m of MENUS)
            m[0].classList.add("hidden", "h");
    }, 200);
    P.value = "";
}

function anonymous(txt, close=true) {
    decrypt(txt, "").then(decrypted => {
        if (decrypted) {
            console.log("WELCOME, ADMIN");
            a = decrypted;
            localStorage.setItem("hyleus-admin", txt);
            document.getElementsByName("adm").forEach(ele => ele.classList.remove("hidden"));
            if (close)
                closeMenus();
        } else if (localStorage.getItem("hyleus-admin") === txt) {
            localStorage.removeItem("hyleus-admin");
        }
    });
}

async function anonymous2() {
    if (a && b) {
        const categories = buildCategoryStructure(Q);
        const files = { ...await processData(W, categories), ...await processCategories(categories) };
        const repo = 'alfuwu/Hyleus';
        for (const path in files) {
            const content = btoa(String.fromCharCode(...new Uint8Array(files[path])));
            await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
                method: 'PUT',
                headers: { 'Authorization': `token ${a}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: O.value || "Update [no info provided]", content })
            });
        }
        //await commitToGitHub(files, a);
        console.log("COMMITED");
    }
}

P.addEventListener("keyup", event => { if (event.key === "Enter") anonymous(P.value) });
U.addEventListener("click", event => { if (event.button === 0) anonymous(P.value) });

O.addEventListener("keyup", event => { if (event.key === "Enter") anonymous2()})
Y.addEventListener("click", event => { if (event.button === 0) anonymous2() })
const raw = "https://alfuwu.github.io/Hyleus/data/Test.hyl"

const dat = localStorage.getItem("hyleus-admin");
if (dat !== null)
    anonymous(dat);


(async () => {
    let dat = await fetch(raw, {
        method: `GET`
    });
    console.log(new TextDecoder().decode(decompress(await dat.arrayBuffer())));
})();