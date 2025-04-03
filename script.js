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
const B = document.getElementById("article");
const I = document.getElementById("locked-article");
const D = document.getElementById("create-form");
const H = document.getElementById("unencrypt");
const Y = document.getElementById("save");
const O = document.getElementById("s");
const T = document.getElementById("tree");
const Q = []; // {id: uuid4, name: "Text", parent: null/parent uuid4, description: "Markdown text", position: number}
const W = []; // {title: "Text", category: null/category uuid4, type: int, content: "Markdown text", password: null/"password", salt: Uint8Array, key: CryptoKey, iv: Uint8Array, encrypted: true/null, position: number}

const AR = document.getElementById("ar");
const BT = document.getElementById("by-type");
const MP = document.getElementById("maps");

// article types
const ARTICLE = 0; // normal article

const MENUS = [[K, C], [J, L], [G, V]];
const CONTENTS = [N, B, I, D];
const NAV_BUTTONS = [AR, BT, MP];

let guh = localStorage.getItem("hyleus-admin");
let a = null;
let b = true;
let c = null;
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

async function getEncryptionData(encryptedData, password=null) {
    const base32 = password instanceof Uint8Array ? password : Uint8Array.from(atob(password ? password : A), c => c.charCodeAt(0));
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
        ["encrypt", "decrypt"]
    );
    
    const decryptedKey = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: salt, tagLength: 128 },
        encryptedKey,
        new Uint8Array([...tag, ...encryptedCompressedText])
    );
    return {
        salt: salt,
        iv: iv,
        encKey: encryptedKey,
        key: decryptedKey
    };
}

async function decrypt(encryptedData, password=null, compressed=false) {
    try {
        const data = await getEncryptionData(encryptedData, password);
        return new TextDecoder().decode(compressed ? decompress(new Uint8Array(data.key)) : data.key);
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

async function encodeAndEncrypt(content, category, type, password, salt, key, iv, encrypted, position) {
    let data = content instanceof Uint8Array ? content : new TextEncoder().encode(content);

    if (!encrypted)
        if (salt && key && iv)
            data = await baseEncrypt(data, salt, key, iv, true, true);
        else if (password)
            data = await encrypt(content, password, true, true);

    const buffer = new ArrayBuffer(21 /*22*/);
    const view = new DataView(buffer);
    new Uint8Array(buffer, 0, 16).set(uuidToBinary(category));
    view.setUint32(16, position, true);
    view.setUint8(20, encrypted || salt && key && iv || password ? 1 : 0);
    //view.setUint8(21, type || 0);
    return compress(concatenate(new Uint8Array(buffer), data));
}

function buildCategoryStructure(Q) {
    const categories = {};
    Q.forEach(({ id, name, parent, description, position }) => {
        categories[id] = { name, parent, description, path: parent ? null : `data/${name}`, position };
    });
    Object.values(categories).forEach(category => {
        if (category.parent)
            category.path = `${categories[category.parent].path}/${category.name}`;
    });
    return categories;
}

function concatenate(arr1, arr2) {
    const concatenated = new Uint8Array(arr1.length + arr2.length);
    concatenated.set(arr1);
    concatenated.set(arr2, arr1.length);
    return concatenated;
}

function uuidToBinary(uuid) {
    return uuid ? new Uint8Array(uuid.match(/\w{2}/g).map(byte => parseInt(byte, 16))) : new Uint8Array(16).fill(0);
}

function binaryToUuid(binary) {
    const data = Array.from(binary).map(byte => byte.toString(16).padStart(2, '0')).join('');
    return data === "00000000000000000000000000000000" ? null : data;
}

function generateUuid() {
    try {
        return crypto.randomUUID().replace("-", "");
    } catch (e) {
        return "10000000100040008000100000000000".replace(/[018]/g, c =>
            (+c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> +c / 4).toString(16)
        );
    }
}

async function processData(W, categories) {
    const files = {};
    for (const item of W) {
        const categoryPath = item.category ? categories[item.category]?.path : 'data';
        const filePath = `${categoryPath}/${item.title}.hyl`;
        files[filePath] = await encodeAndEncrypt(item.content, item.category, item.type, item.password, item.salt, item.key, item.iv, item.encrypted, item.position);
    }
    return files;
}

async function processCategories(categories) {
    const files = {};
    for (const id in categories) {
        const category = categories[id];
        const filePath = `${category.path}/category.info`;
        const data = new TextEncoder().encode(category.description || '');
        const buffer = new ArrayBuffer(36);
        const view = new DataView(buffer);
        new Uint8Array(buffer, 0, 16).set(uuidToBinary(id));
        new Uint8Array(buffer, 16, 16).set(uuidToBinary(category.parent));
        view.setUint32(32, category.position, true);
        files[filePath] = compress(concatenate(new Uint8Array(buffer), data));
    }
    return files;
}

async function commitToGitHub(files, token) {
    const repo = 'alfuwu/Hyleus';
    const blobs = [];
    /*
        for (const path in files) {
            const content = arrToB64(new Uint8Array(files[path]));
            let sha = null;
            try {
                const exists = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
                    method: 'GET',
                    headers: { 'Authorization': `token ${a}` }
                });
                if (exists.ok)
                    sha = (await exists.json()).sha;
            } catch (_) { }
            await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
                method: 'PUT',
                headers: { 'Authorization': `token ${a}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: O.value || "Update [no info provided]", content, sha })
            });
        }
    */
    for (const path in files) {
        const content = arrToB64(new Uint8Array(files[path]));
        const resp = await fetch(`https://api.github.com/repos/${repo}/git/blobs`, {
            method: 'POST',
            headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json', 'accept': 'application/vnd.github+json' },
            body: JSON.stringify({ content, encoding: "base64" })
        });
        blobs.push({path, mode: "100644", type: "blob", sha: (await resp.json()).sha});
    }
    const baseTree = await fetch(`https://api.github.com/repos/${repo}/git/trees/master`, {
        method: 'GET',
        headers: { 'accept': 'application/vnd.github+json' }
    });
    const bgase = await fetch(`https://api.github.com/repos/${repo}/git/trees`, {
        method: 'POST',
        headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json', 'accept': 'application/vnd.github+json' },
        body: JSON.stringify({ base_tree: (await baseTree.json()).sha, tree: blobs })
    });
    const branch = await fetch(`https://api.github.com/repos/${repo}/git/refs/heads/master`, {
        method: 'GET',
        headers: { 'accept': 'application/vnd.github+json' }
    });
    const commit = await fetch(`https://api.github.com/repos/${repo}/git/commits`, {
        method: 'POST',
        headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json', 'accept': 'application/vnd.github+json' },
        body: JSON.stringify({ tree: (await bgase.json()).sha, message: O.value || "Update [no info provided]", parents: [(await branch.json()).object.sha] })
    });
    const ret = await commit.json()
    await fetch(`https://api.github.com/repos/${repo}/git/refs/heads/master`, {
        method: 'PATCH',
        headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json', 'accept': 'application/vnd.github+json' },
        body: JSON.stringify({ sha: ret.sha })
    });
    return ret;
}

function arrToB64(arr) {
    return btoa(String.fromCharCode(...arr));
}

function b64ToArr(b64) {
    return new Uint8Array(atob(b64).split("").map(c => { return c.charCodeAt(0); }));
}

async function decodeFile(path) {
    const dat = await fetch(`https://alfuwu.github.io/Hyleus/data/${path}`, {
        method: 'GET'
    });
    const ab = await dat.arrayBuffer();
    const decomp = decompress(ab);
    let encrypted = decomp[20] == 1;
    //const type = decomp[21];
    let text = decomp.slice(21);
    if (text[0] === 0)
        text = decomp.slice(22);
    let salt, key, iv;
    if (encrypted && guh) {
        try {
            const data = await getEncryptionData(guh, text);
            salt = data.salt;
            key = data.encKey;
            iv = data.iv;
            text = decompress(new Uint8Array(data.key));
            encrypted = false;
        } catch (e) {
            //console.warn(e);
        }
    }
    return {
        title: path.split("/").at(-1).slice(0, -4),
        category: binaryToUuid(decomp.slice(0, 16)),
        type: 0,
        content: encrypted ? text : new TextDecoder().decode(text),
        tags: [],
        salt, key, iv,
        encrypted,
        position: new DataView(decomp.slice(16, 20).buffer).getUint32(0, true)
    };
}

async function decodeDir(path) {
    const dat = await fetch(`https://alfuwu.github.io/Hyleus/data/${path}`, {
        method: 'GET'
    });
    const decomp = decompress(await dat.arrayBuffer());
    return {
        id: binaryToUuid(decomp.slice(0, 16)),
        name: path.split("/").at(-2),
        parent: binaryToUuid(decomp.slice(16, 32)),
        description: new TextDecoder().decode(decomp.slice(36)),
        position: new DataView(decomp.slice(32, 36).buffer).getUint32(0, true)
    };
}

function showContent(ele) {
    for (const content of CONTENTS)
        if (content !== ele)
            content.classList.add("hidden");
    ele.classList.remove("hidden");
}

function loadFile() {
    if (c === null)
        return;
    console.log(c);
    if (c.encrypted) {
        showContent(I);
    } else {
        switch (c.type) {
            case ARTICLE: {
                showContent(B);
                B.textContent = c.content;
            }
        }
    }
}

function createTreeItem(text, dat) {
    const folder = dat instanceof HTMLElement;
    const obj = document.createElement("button");
    obj.classList.add("hflex", "left", "fold");
    const ico = document.createElement("img");
    ico.classList.add("smol", "inv", "ico", "padr");
    ico.src = folder ? "folder.svg" : "article.svg";
    obj.appendChild(ico);
    obj.appendChild(document.createTextNode(text));
    if (folder)
        obj.addEventListener("click", event => {
            if (event.button === 0)
                dat.classList.toggle("hidden");
        });
    else
        obj.addEventListener("click", event => {
            if (event.button === 0) {
                c = dat;
                loadFile();
            }
        })
    return obj;
}

function constructTree() {
    T.innerHTML = ``; // remove all children
    const categoryToFileMap = W.reduce((acc, { title, category, type, content, password, salt, key, iv, encrypted, position }) => {
        if (!acc[category])
          acc[category] = [];
        acc[category].push({ title, category, type, content, password, salt, key, iv, encrypted, position });
        return acc;
      }, {});
    for (const folder of Q) {
        const children = document.createElement("div");
        if (folder.id in categoryToFileMap) {
            children.classList.add("big", "padl");
            for (const child of categoryToFileMap[folder.id])
                children.append(createTreeItem(child.title, child));
        }
        T.appendChild(createTreeItem(folder.name, children));
        T.append(children);
    }
    for (const file of W)
        if (file.category === null)
            T.appendChild(createTreeItem(file.title, file));
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

for (const navButton of NAV_BUTTONS)
    navButton.addEventListener("click", event => {
        if (event.button === 0) {
            for (const nbtn of NAV_BUTTONS)
                if (nbtn !== navButton)
                    nbtn.classList.remove("selected");
            navButton.classList.add("selected");
        }
    });

function anonymous(txt, close=true) {
    decrypt(txt, "").then(decrypted => {
        if (decrypted) {
            a = decrypted;
            guh = txt;
            localStorage.setItem("hyleus-admin", txt);
            document.getElementsByName("adm").forEach(ele => ele.classList.remove("hidden"));
            if (close)
                closeMenus();
        } else if (localStorage.getItem("hyleus-admin") === txt) {
            localStorage.removeItem("hyleus-admin");
            guh = null;
        }
    });
}

async function anonymous2() {
    if (a && b) {
        const categories = buildCategoryStructure(Q);
        const files = { ...await processData(W, categories), ...await processCategories(categories) };
        await commitToGitHub(files, a);
        console.log("COMMITED");
    }
}

P.addEventListener("keyup", event => { if (event.key === "Enter") anonymous(P.value) });
U.addEventListener("click", event => { if (event.button === 0) anonymous(P.value) });

O.addEventListener("keyup", event => { if (event.key === "Enter") anonymous2()});
Y.addEventListener("click", event => { if (event.button === 0) anonymous2() });

H.addEventListener("keyup", async (event) => {
    if (event.key === "Enter" && c) {
        try {
            const data = await getEncryptionData(H.value, c.content);
            c.salt = data.salt;
            c.key = data.encKey;
            c.iv = data.iv;
            c.content = new TextDecoder().decode(decompress(new Uint8Array(data.key)));
            c.encrypted = false;
            loadFile();
        } catch (e) {
            console.warn(e);
        }
    }
});

if (guh !== null)
    anonymous(guh);

(async () => {
    const files = await (await fetch("https://alfuwu.github.io/Hyleus/data/files.json", {
        method: 'GET'
    })).json();
    for (const file of files) {
        if (file.endsWith(".hyl")) {
            const decoded = await decodeFile(file);
            console.log("FILE", decoded);
            W.push(decoded);
        } else if (file.endsWith("/category.info")) {
            const decoded = await decodeDir(file);
            console.log("CATEGORY", decoded);
            Q.push(decoded);
        }
    }
    console.log(W);
    constructTree();
})();
