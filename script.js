// spicy!
const A = "zKMTNa/piUlaWk17gdf84QpnNDA2lDEuJ2BpAxlzT029+zn5k55nkLOKGkoi6XzrLI4UaCv7DhC4fYhA9f0inC0s8Nk22okLJXhjSXOjHzuvmZwqBRN1l9wFiPuYIDfPWUtZfBzj0E0cCeN1DI+whTQfwdsNCTFlmj9C8hRUTZBE8sy7RDbwnIU=";
const S = document.getElementById("search");
const Z = document.getElementById("search-text");
const C = document.getElementById("sbtn");
const E = document.getElementById("cbtn");
const V = document.getElementById("vbtn");
const L = document.getElementById("abtn");
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
// folder.id is really quite useless, but it'd be a pain to remove it atp so it stays :shrug:
let Q = []; // {id: null, name: "Text", parent: null, description: "Markdown text", position: 1}
let W = []; // {title: "Text", category: null, type: 0, content: "Markdown text", password: null, salt: undefined, key: undefined, iv: undefined, encrypted: false, position: 1}
const X = new Set();
const DEL = new Set();

const AR = document.getElementById("ar");
//const BT = document.getElementById("by-type");
const MP = document.getElementById("maps");

const HR = document.getElementById("hierarchy");
const HC = document.getElementById("hierarchy-context-menu");
const HFE = document.getElementById("hierarchy-file-context-menu");
const HFR = document.getElementById("hierarchy-folder-context-menu");

const CA = document.getElementById("categories");

const AN = document.getElementById("article-title");
const AT = document.getElementById("article-data");
const AC = document.getElementById("article-category");
const AD = document.getElementById("article-create");
const AP = document.getElementById("article-password");
const UP = document.getElementById("uap");

const M = document.getElementById("menus");
const K = document.getElementById("search-menu");
const J = document.getElementById("admin-menu");
const G = document.getElementById("save-menu");
const FM = document.getElementById("folder-menu");
const LO = document.getElementById("loading");

const FH = document.getElementById("fold-head");
const FN = document.getElementById("fold-name");
const FC = document.getElementById("fold-parent");
const FT = document.getElementById("fold-desc");
const FD = document.getElementById("fold-create");

// article types
const ARTICLE = 0; // normal article

const MENUS = [[K, C], [J, L], [G, V], [FM, null]];
const CONTENTS = [N, B, I, D];
const NAV_BUTTONS = [AR, /*BT,*/ MP];
const CONTEXT_MENUS = [HC, HFE, HFR];

const MARQUEE = new ResizeObserver(entries => {
    for (let entry of entries) {
        if (entry.target.scrollWidth > entry.contentRect.width) {
            entry.target.style.setProperty("--width", `-${entry.target.scrollWidth + 5}px`);
            entry.target.classList.add("mq");
        } else {
            entry.target.classList.remove("mq");
        }
    }
});

let paths = [];

let guh = localStorage.getItem("hyleus-admin");
let a = null;
let b = true; // idr what this variable was for
let c = null;
let d = null;

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
    const ret = compress(concatenate(new Uint8Array(buffer), data));
    if (!encrypted && (salt && key && iv || password)) { // make sure that the data is decryptable
        const text = decompress(b64ToArr(arrToB64(ret))).slice(21);
        try {
            if (password)
                await getEncryptionData(password, text);
            else
                await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv, tagLength: 128 },
                    key,
                    new Uint8Array([...text.slice(44), ...text.slice(28, 44)])
                );
        } catch (e) {
            console.warn("Encryption failed");
            return null;
        }
    }
    return ret;
}

function buildCategoryPath(categories, name, parent) {
    if (parent && !categories[parent].path)
        categories[parent].path = buildCategoryPath(categories, categories[parent].name, categories[parent].parent);
    return `${parent ? categories[parent].path : "data"}/${name}`;
}

function buildCategoryStructure(Q) {
    const categories = {};
    Q.forEach(({ id, name, parent, description, position }) => {
        categories[id] = { name, parent, description, path: null, position };
    });
    Object.values(categories).forEach(category => category.path = buildCategoryPath(categories, category.name, category.parent));
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
        return crypto.randomUUID().replaceAll("-", "");
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
        if (!categoryPath)
            continue;
        if (!X.has(`${categoryPath}/${item.title}`.substring(5)))
            continue; // don't add files if they haven't been changed
        const filePath = `${categoryPath}/${item.title}.hyl`;
        for (let i = 0; i < 5; i++) { // 5 encryption attempts (idk if encryption is the problem or what, but for some reason some encrypted files will randomly stop working, sooo)
            const data = await encodeAndEncrypt(item.content, item.category, item.type, item.password, item.salt, item.key, item.iv, item.encrypted, item.position);
            if (data !== null) { // encryption may fail(?), so don't override if it does
                files[filePath] = data;
                break;
            }
        }
    }
    return files;
}

async function processCategories(categories) {
    const files = {};
    for (const id in categories) {
        if (!X.has(id))
            continue;
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

// this function won't work if there isn't already a commit in the repo
async function commitToGitHub(files, token) {
    if (Object.keys(files).filter(v => !DEL.has(v)).length + [...DEL].filter(v => !Object.keys(files).includes(v)).length === 0) {
        DEL.clear();
        console.warn("Commit is empty; aborting");
        return; // don't create empty commits
    }
    const repo = 'alfuwu/Hyleus';
    const blobs = [];
    const paths = await (await fetch(`https://alfuwu.github.io/Hyleus/data/files.json`, {
        method: 'GET'
    })).json();
    for (const path of DEL)
        if (path.endsWith("/") && paths.indexOf(path + "category.info") !== -1 || paths.indexOf(path + ".hyl") !== -1) // don't delete categories or files that don't exist in the repo
            blobs.push({ path: "data/" + (path.endsWith("/") ? path.slice(0, -1) : path + ".hyl"), mode: path.endsWith("/") ? "040000" : "100644", sha: null });
    DEL.clear();
    for (const path in files) {
        const resp = await fetch(`https://api.github.com/repos/${repo}/git/blobs`, {
            method: 'POST',
            headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json', 'accept': 'application/vnd.github+json' },
            body: JSON.stringify({ content: arrToB64(new Uint8Array(files[path])), encoding: "base64" })
        });
        blobs.push({ path, mode: "100644", type: "blob", sha: (await resp.json()).sha });
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
    return new Uint8Array(atob(b64).split('').map(c => c.charCodeAt(0)));
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
    let salt, key, iv, password;
    if (encrypted && guh) {
        try {
            const data = await getEncryptionData(guh, text);
            salt = data.salt;
            key = data.encKey;
            iv = data.iv;
            text = decompress(new Uint8Array(data.key));
            encrypted = false;
            password = guh;
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
        salt, key, iv, password,
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

function showContextMenu(ele, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    for (const ctxMenu of CONTEXT_MENUS)
        ctxMenu.classList.add("hidden");
    ele.style.left = event.pageX + "px";
    ele.style.top = event.pageY  + "px";
    ele.classList.remove("hidden");
}

function loadFile() {
    if (c === null) {
        showContent(N);
        return;
    }
    if (c.encrypted) {
        showContent(I);
    } else {
        switch (c.type) {
            case ARTICLE: {
                showContent(B);
                B.innerHTML = `<h1>${c.title}</h1><hr>\n${permParse(c.content)}`;
            }
        }
    }
}

async function loadFold() {
    const existing = Q.find(v => v.name === d.name && v.path === d.path);
    const decoded = !existing || !existing.id ? await decodeDir(d.path + "category.info") : null;
    if (decoded) {
        console.log("CATEGORY", decoded);
        if (existing)
            Object.assign(existing, {
                ...decoded
            });
        else
            Q.push(await decodeDir(d.path + "category.info"));
    }
}

async function loadCat(cat) {
    let prev = "";
    console.log(cat);
    let parentId = null;
    for (const dir of cat) {
        currentFolder = Q.find(v => v.name === dir && v.parent === parentId);
        parentId = currentFolder?.id;
        if (currentFolder?.temp) // don't attempt to load folders that were created in session
            return;
        prev += dir + "/";
        const existing = Q.find(v => v.name === dir && (v.path === prev));
        const decoded = !existing || !existing.id ? await decodeDir(prev + "category.info") : null;
        if (decoded) {
            console.log("CATEGORY", decoded);
            if (existing)
                Object.assign(existing, {
                    ...decoded
                });
            else
                Q.push(await decodeDir(prev + "category.info"));
        }
    }
}

async function loadDat(dat) {
    if (dat.path && !dat.temp) {
        const decoded = await decodeFile(dat.path);
        console.log(dat.path);
        if (dat.path.includes("/"))
            loadCat(dat.path.split("/").slice(0, -1));
        delete dat.path;
        Object.assign(dat, {
            ...decoded
        });
        console.log("FILE", dat);
    }
}

function createTreeItem(text, dat, children = null) {
    const obj = document.createElement("button");
    obj.classList.add("hflex", "left", "fold");

    const ico = document.createElement("img");
    ico.classList.add("smol", "inv", "ico", "padr");
    ico.src = children ? "folder.svg" : "article.svg";

    const wrapper = document.createElement("div");
    wrapper.classList.add("yuh");
    const txt = document.createElement("div");
    txt.textContent = text;

    wrapper.appendChild(txt);
    
    MARQUEE.observe(txt);

    obj.appendChild(ico);
    obj.appendChild(wrapper);
    if (children) {
        const existing = Q.find(v => formatFileName(v) === dat.path || v.path === dat.path);
        if (existing)
            dat = existing;
        else
            Q.push(dat);
        obj.addEventListener("click", event => {
            if (event.button === 0)
                children.classList.toggle("hidden");
        });
        obj.addEventListener("contextmenu", async event => { if (a) { d = dat; showContextMenu(HFR, event); await loadFold() } });
    } else {
        const existing = W.find(v => formatFileName(v) === dat.path || v.path === dat.path);
        if (existing)
            dat = existing;
        else
            W.push(dat);
        dat.obj = obj;
        obj.addEventListener("click", async event => {
            if (event.button === 0) {
                if (c)
                    c.obj.classList.remove("selected");
                c = c === dat ? null : dat;
                if (c) {
                    obj.classList.add("selected");
                    await loadDat(dat);
                }
                loadFile();
            }
        });
        obj.addEventListener("contextmenu", async event => { if (a) { d = dat; showContextMenu(HFE, event); await loadDat(dat) } });
        if (c === dat)
            obj.classList.add("selected");
    }
    return obj;
}

function handleTreeFromPath(name, subtree, path = "") {
    if (subtree.path || subtree.title)
        return createTreeItem(name.slice(0, -4), subtree);

    const children = document.createElement("div");
    children.classList.add("big", "padl", "hidden");

    for (const key of Object.keys(subtree).sort()) {
        const item = handleTreeFromPath(key, subtree[key], path + name + "/");
        if (item instanceof Array) {
            children.appendChild(item[0]);
            children.appendChild(item[1]);
        } else {
            children.appendChild(item);
        }
    }

    const folderData = { name, path: (path || "") + name + "/" };
    return [createTreeItem(name, folderData, children), children];
}

function buildPathTree(paths) {
    const root = {};
    for (const path of paths) {
        const parts = path.split("/");
        let current = root;
        for (let i = 0; i < parts.length; i++) {
            const part = parts[i];
            if (i === parts.length - 1) {
                if (path.endsWith(".hyl")) {
                    const existing = W.find(v => v.title === path.split("/").pop().slice(0, -4) && formatFileName(Q.find(q => q.id === v.category)).slice(0, -1) === path.split("/").slice(0, -1).join("/"));
                    current[part] = existing || { path };
                }
            } else {
                if (!current[part]) current[part] = {};
                current = current[part];
            }
        }
    }
    return root;
}

function constructTree() {
    const pathTree = buildPathTree(paths);

    T.innerHTML = ``;
    for (const [name, subtree] of Object.entries(pathTree)) {
        const item = handleTreeFromPath(name, subtree);
        if (item instanceof Array) {
            T.appendChild(item[0]);
            T.appendChild(item[1]);
        } else {
            T.appendChild(item);
        }
    }
}

function constructCategoriesList() {
    CA.innerHTML = ``;
    for (const child of paths) {
        if (child.endsWith("/category.info")) {
            const opt = document.createElement("option");
            opt.value = child.slice(0, -14);
            CA.appendChild(opt);
        }
    }
}

function opacitate(ele, startOpac, endOpac) {
    ele.animate([
        { opacity: startOpac },
        { opacity: endOpac }
    ], {
        duration: 200,
        fill: "forwards",
        easing: "ease-in-out"
    });
}

function closeMenus(fun = null) {
    opacitate(F, 0.5, 0);
    for (const m of MENUS)
        opacitate(m[0], 1, 0);
    setTimeout(() => {
        M.classList.add("hidden");
        F.classList.add("h");
        for (const m of MENUS)
            m[0].classList.add("hidden", "h");
        if (fun !== null)
            fun();
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
        LO.classList.remove("h");
        opacitate(LO, 0, 1);
        const categories = buildCategoryStructure(Q);
        const files = { ...await processData(W, categories), ...await processCategories(categories) };
        X.clear();
        await commitToGitHub(files, a);
        console.log("COMMITED");
        opacitate(LO, 1, 0);
        setTimeout(() => {
            LO.classList.add("h");
        }, 200);
        closeMenus();
    }
}

async function anonymous3() {
    if (FN.value) {
        const folder = {
            id: generateUuid(),
            name: FN.value,
            parent: (await findFolderByPath(FC.value))?.id || null,
            description: FT.innerText,
            position: 1,
            temp: true
        }
        const existing = findExistingFold();
        if (existing !== -1)
            Q[existing] = folder;
        else
            Q.push(folder);
        X.add(folder.id);
        paths.push(formatFileName(folder) + "category.info");
        closeMenus(() => { FN.value = ""; FT.innerText = ""; FT.classList.add("phtxt"); FN.classList.remove("warn"); updateFD() });
        constructTree();
        constructCategoriesList();
    } else if (!FN.value) {
        FN.classList.add("warn");
    }
}

function parse(text) {
    let md = text
        .replace(/</gm, "&lt;")
        .replace(/^(#{1,6}) (.+)$/gm, (_, header, content) => { return `<span class="h${header.length}"><span class="mds">${header}</span> ${content}</span>`; })
        .replace(/^-# (.+)$/gm, '<span class="st"><span class="mds"><b>-#</b></span> $1</span>')
        .replace(/~~(.+?[^\\])~~/gm, '<span class="mds">~~</span><s>$1</s><span class="mds">~~</span>') // strikethrough
        .replace(/(^|[^_\\])__([^_]+?[^\\_])__($|[^_])/gm, '$1<span class="mds">__</span><u>$2</u><span class="mds">__</span>$3') // underlined
        .replace(/(^|[^_\\\w])_([^_]+?[^\\_])_($|[^_\w])/gmi, '$1<span class="mds">_</span><i>$2</i><span class="mds">_</span>$3') // italic text
        .replace(/(^|[^*\\])\*\*\*([^*]+?[^\\*])\*\*\*($|[^*])/gm, '$1<span class="mds">***</span><b><i>$2</i></b><span class="mds">***</span>$3') // italic bold text
        .replace(/(^|[^*\\])\*\*([^*]+?[^\\*])\*\*($|[^*])/gm, '$1<span class="mds">**</span><b>$2</b><span class="mds">**</span>$3') // bold text
        .replace(/(^|[^*\\])\*([^*]+?[^\\*])\*($|[^*])/gm, '$1<span class="mds">*</span><i>$2</i><span class="mds">*</span>$3') // italic text
        .replace(/(^|[^`\\])```([\s\S]+?[^`\\])```($|[^`])/gm, '$1<span class="mds">```</span><span class="multiline-code">$2</span><span class="mds">```</span>$3') // multiline code
        .replace(/(^|[^`\\])`([^`]+?[^`\\])`($|[^`])/g, '$1<span class="mds">`</span><code>$2</code><span class="mds">`</span>$3') // code
        .replace(/(^|[^\\])\|\|(.+?[^\\])\|\|/g, '$1<span class="mds">||</span><span class="spoiler-edit">$2</span><span class="mds">||</span>') // spoilers
        .replace(/\[(.*?)\]\((https?:\/\/[^\s)]+)\)|({https?:\/\/[^\s/$.?#].[^\s]*})|(https?:\/\/[^\s/$.?#].[^\s]*)/gm, (_, formatText, formatLink, inlineDataLink, link) => formatText && formatLink ? `<a data-text="[${formatText}](${formatLink})"><span class="mds">[</span>${formatText}<span class="mds">](${formatLink})</span></a>` : inlineDataLink ? `<span class="mds">{</span><a data-text="${inlineDataLink.slice(1, -1)}">${inlineDataLink.slice(1, -1)}</a><span class="mds">}</span>` : `<a data-text="${link}">${link}</a>`); // links must go last because of the data-text attribute
    const refMap = {};
    Object.values(paths).forEach(path => {
        if (path.endsWith(".hyl")) {
            const fileName = path.split("/").pop();
            const key = fileName.slice(0, -4);
            const dir = path.split("/").slice(0, -1).join("/");
            const replacement = `<a class="ref" data-text="@${key}"><span class="mds">@</span>${key}</a>`;
            refMap[key] = replacement;
        }
    });
    const sortedKeys = Object.keys(refMap).sort((a, b) => b.length - a.length);
    const regex = new RegExp(`@(${sortedKeys.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\b`, 'g');
    md = md.replace(regex, (_, match) => refMap[match]);
    return md;
}

function permParse(text) {
    let md = text
        .replace(/</gm, "&lt;")
        .replace(/^(#{1,6}) (.+)$/gm, (_, header, content) => `<span class="h${header.length}" id="${content.replaceAll(" ", "-").toLowerCase()}">${content}</span>`)
        .replace(/^-# (.+)$/gm, '<span class="st">$1</span>')
        .replace(/~~(.+?[^\\])~~/gm, '<s>$1</s>') // strikethrough
        .replace(/(^|[^_\\])__([^_]+?[^\\_])__($|[^_])/gm, '$1<u>$2</u>$3') // underlined
        .replace(/(^|[^_\\\w])_([^_]+?[^\\_])_($|[^_\w])/gm, '$1<i>$2</i>$3') // italic text
        .replace(/(^|[^*\\])\*\*\*([^*]+?[^\\*])\*\*\*($|[^*])/gm, '$1<b><i>$2</i></b>$3') // italic bold text
        .replace(/(^|[^*\\])\*\*([^*]+?[^\\*])\*\*($|[^*])/gm, '$1<b>$2</b>$3') // bold text
        .replace(/(^|[^*\\])\*([^*]+?[^\\*])\*($|[^*])/gm, '$1<i>$2</i>$3') // italic text
        .replace(/```\n?([\s\S]+?)\n?```\n?/gm, '<pre><code>$1</code></pre>') // multiline code
        .replace(/`([^`]+?)`/g, '<code>$1</code>') // code
        .replace(/\|\|(.+?)\|\|/g, '<span class="spoiler">$1</span>') // spoilers
        .replace(/(?:^|\n)((?:- .+(?:\n|$))+)/g, (_, list) =>
            `<ul>${list.trim().split(/\n/).map(item => `<li>${item.replace(/^- /, '')}</li>`).join('')}</ul>`) // unordered lists
        .replace(/(?:^|\n)((?:(\d+)\. .+(?:\n|$))+)/g, (_, list) =>
            `<ol>${list.trim().split(/\n/).map(item => `<li>${item.replace(/^\d+\. /, '')}</li>`).join('')}</ol>`) // ordered lists
        .replace(/(?:^|\n)((?:(?=[IVXLCDM]+\.)[IVXLCDM]+\. .+(?:\n|$))+)/gmi, (_, list) =>
            `<ol type="I">${list.trim().split(/\n/).map(item => `<li>${item.replace(/^[IVXLCDM]+\. /i, '')}</li>`).join('')}</ol>`) // ordered lists (roman numerals)
        .replace(/\[(.*?)\]\((https?:\/\/[^\s)]+)\)|({https?:\/\/[^\s/$.?#].[^\s]*})|(https?:\/\/[^\s/$.?#].[^\s]*)/gm, (match, formatText, formatLink, inlineDataLink, link, offset, fullText) => {
            if (formatText && formatLink) {
                return `<a data-text="[${formatText}](${formatLink})"><span class="mds">[</span>${formatText}<span class="mds">](${formatLink})</span></a>`
            } else if (inlineDataLink) {
                const url = inlineDataLink.slice(1, -1);

                const hasTextBefore = offset !== 0 && fullText[offset - 1] !== "\n"
                const hasTextAfter = fullText.length > offset + match.length + 1 && fullText[offset + match.length + 1] !== "\n";

                const determineFloatClass = () => hasTextBefore && !hasTextAfter ? "float-right" : hasTextAfter && !hasTextBefore ? "float-left" : hasTextBefore && hasTextAfter ? "" : "float-center";
                
                const youtubeMatch = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([\w-]{11})/);
                if (youtubeMatch)
                    return `<iframe class="inline-embed ${determineFloatClass()}" src="https://www.youtube.com/embed/${youtubeMatch[1]}" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>`;

                if (url.includes("open.spotify.com"))
                    return `<iframe class="inline-embed ${determineFloatClass()}" src="${url.replace("open.spotify.com", "open.spotify.com/embed")}" frameborder="0" allowtransparency="true" allow="encrypted-media"></iframe>`;

                if (url.includes("soundcloud.com"))
                    return `<iframe class="inline-embed ${determineFloatClass()}" width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=${encodeURIComponent(url)}&color=%23ff5500&auto_play=false&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true&visual=false"></iframe>`;

                const ext = url.split('.').pop().split('?')[0].toLowerCase();
                if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'].includes(ext) || url.startsWith("https://tenor.com/")) {
                    return `<img src="${url}" class="inline-img ${determineFloatClass()}">`;
                }  else if (['mp4', 'webm', 'ogv', 'mkv'].includes(ext)) {
                    return `<video controls class="inline-video ${determineFloatClass()}"><source src="${url}" type="video/${ext}">Your browser does not support the video tag.</video>`;
                } else if (['mp3', 'ogg', 'oga', 'wav', 'aac', 'flac', 'm4a'].includes(ext)) {
                    return `<audio controls src="${url}" class="inline-audio ${determineFloatClass()}"></audio>`;
                } else {
                    return `<details class="inline-file"><summary>File Preview: ${url.split('/').pop().split('?')[0]}</summary><iframe src="${url}" sandbox class="file-preview-frame"></iframe></details>`;
                }
            } else {
                return `<a href="${link}" data-text="${link}" target="_blank">${link}</a>`
            }
        }); // links
    const refMap = {};
    Object.values(paths).forEach(path => {
        if (path.endsWith(".hyl")) {
            const fileName = path.split("/").pop();
            const key = fileName.slice(0, -4);
            const dir = path.split("/").slice(0, -1).join("/");
            const replacement = `<a class="ref" onclick="if (c === null || c.title !== '${key}' && formatFileName(Q.find(q => q.id === c.category)) !== '${dir}/') W.find(v => v.title === '${key}' && formatFileName(Q.find(q => q.id === v.category)) === '${dir}/' || v.path && v.path.split('/').pop() === '${fileName}').obj.click();" data-text="${key}">${key}</a>`;
            refMap[key] = replacement;
        }
    });
    const sortedKeys = Object.keys(refMap).sort((a, b) => b.length - a.length);
    const regex = new RegExp(`@(${sortedKeys.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\b`, 'g');
    md = md.replace(regex, (_, match) => refMap[match]);
    return md;
}

function restore(context, selection, len) {
    let pos = getTextNodeAtPosition(context, len);
    selection.removeAllRanges();
    let range = new Range();
    range.setStart(pos.node, pos.position);
    selection.addRange(range);
}

function getTextNodeAtPosition(root, index) {
    const NODE_TYPE = NodeFilter.SHOW_TEXT;
    let treeWalker = document.createTreeWalker(root, NODE_TYPE, function next(elem) {
        if (index > elem.textContent.length){
            index -= elem.textContent.length;
            return NodeFilter.FILTER_REJECT
        }
        return NodeFilter.FILTER_ACCEPT;
    });
    const node = treeWalker.nextNode();
    return {
        node: node ? node : root,
        position: index
    };
}

function diffStrings(oldStr, newStr) {
    let start = 0;
    
    while (start < oldStr.length && start < newStr.length && oldStr[start] === newStr[start]) {
        start++;
    }

    let endOld = oldStr.length - 1;
    let endNew = newStr.length - 1;
    while (
        endOld >= start &&
        endNew >= start &&
        oldStr[endOld] === newStr[endNew]
    ) {
        endOld--;
        endNew--;
    }

    const deleted = oldStr.slice(start, endOld + 1);
    const added = newStr.slice(start, endNew + 1);

    return { added, deleted, start, endOld, endNew };
}

function findExisting() {
    return W.findIndex(v => v.title === AN.value && (formatFileName(Q.find(q => q.id === v.category)).slice(0, -1) === AC.value || v.path && v.path.split("/").slice(0, -1).join("/") === AC.value || v.path === AC.value));
}
function findExistingFold() {
    return Q.findIndex(v => v.name === FN.value && formatFileName(Q.find(q => q.id === v.parent)).slice(0, -1) === FC.value);
}

function updateAD() {
    if (findExisting() !== -1) {
        if (AD.textContent !== "Edit")
            AD.textContent = "Edit";
    } else if (AD.textContent !== "Create")
        AD.textContent = "Create"
}
function updateFD() {
    if (findExistingFold() !== -1) {
        if (FD.textContent !== "Edit")
            FD.textContent = "Edit";
        if (FH.textContent !== "EDIT FOLDER")
            FH.textContent = "EDIT FOLDER";
    } else {
        if (FD.textContent !== "Create")
            FD.textContent = "Create";
        if (FH.textContent !== "CREATE FOLDER")
            FH.textContent = "CREATE FOLDER";
    }
}

function formatFileName(file, ret = "") {
    return !file ? ret : file.id ? formatFileName(file.parent ? Q.find(v => v.id === file.parent) : null, file.name + "/" + ret) : formatFileName(file.category ? Q.find(v => v.id === file.category) : null, file.title);
}

async function findFolderByPath(path) {
    if (!path)
        return null;
    const segments = path.split("/");
    await loadCat(segments);
    let parentId = null;
    let currentFolder = null;
  
    for (const name of segments) {
        currentFolder = Q.find(v => v.name === name && v.parent === parentId);
        if (!currentFolder)
            return null;
        parentId = currentFolder.id;
    }
    return currentFolder;
}

function showFolderMenu() {
    updateFD();
    M.classList.remove("hidden");
    F.classList.remove("h");
    FM.classList.remove("hidden", "h");
    opacitate(F, 0, 0.5);
    opacitate(FM, 0, 1);
}

if (guh !== null)
    anonymous(guh);

(async () => {
    paths = await (await fetch(`https://alfuwu.github.io/Hyleus/data/files.json`)).json();
    constructTree();
    constructCategoriesList();
})();

// EVENTS
document.addEventListener("click", () => {
    if (a)
        for (const ctxMenu of CONTEXT_MENUS)
            ctxMenu.classList.add("hidden");
});
document.addEventListener("contextmenu", () => {
    if (a)
        //event.preventDefault();
        for (const ctxMenu of CONTEXT_MENUS)
            ctxMenu.classList.add("hidden");
});
window.addEventListener("beforeunload", event => {
    if (a && (AN.value || AT.value || X.size > 0)) {
        event.preventDefault();
        event.returnValue = true;
    }
});
HR.addEventListener("contextmenu", event => { if (a) showContextMenu(HC, event) });

S.addEventListener("input", () => Z.innerText = S.value ? "SEARCH FOR \"" + S.value.toUpperCase() + "\"" : "");

for (const m of MENUS)
    if (m[1] !== L && m[1])
        m[1].addEventListener("click", event => {
            if (event.button === 0) {
                M.classList.remove("hidden");
                F.classList.remove("h");
                m[0].classList.remove("hidden", "h");
                opacitate(F, 0, 0.5);
                opacitate(m[0], 0, 1);
            }
        });

E.addEventListener("click", event => { if (event.button === 0) showContent(D) });

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

F.addEventListener("click", event => { if (event.button === 0) closeMenus() });

UP.addEventListener("input", () => AP.disabled = UP.checked);
AN.addEventListener("input", () => { AN.value = AN.value.replaceAll("/", ""); updateAD() });
AC.addEventListener("input", () => updateAD());
AD.addEventListener("click", async event => {
    if (event.button === 0 && AN.value) {
        const file = {
            title: AN.value,
            category: (await findFolderByPath(AC.value))?.id || null,
            type: 0,
            content: AT.innerText,
            password: UP.checked ? guh : AP.value || null,
            salt: undefined, key: undefined, iv: undefined,
            encrypted: false,
            position: 1,
            temp: true
        };
        const existing = findExisting();
        if (existing !== -1)
            W[existing] = file;
        else
            W.push(file);
        const fileName = formatFileName(file);
        X.add(fileName);
        paths.push(fileName + ".hyl");
        showContent(c ? B : N);
        AN.value = "";
        AC.value = "";
        AT.innerText = "";
        AP.value = "";
        AN.classList.remove("warn");
        updateAD();
        if (UP.checked)
            UP.click();
        constructTree();
    } else if (!AN.value) {
        AN.classList.add("warn");
    }
});

FN.addEventListener("input", () => { FN.value = FN.value.replaceAll("/", ""); updateFD() });
FC.addEventListener("input", () => updateFD());
FN.addEventListener("keyup", event => { if (event.key === "Enter") anonymous3() });
FD.addEventListener("click", event => { if (event.button === 0) anonymous3() });

P.addEventListener("keyup", event => { if (event.key === "Enter") anonymous(P.value) });
U.addEventListener("click", event => { if (event.button === 0) anonymous(P.value) });

O.addEventListener("keyup", event => { if (event.key === "Enter") anonymous2()});
Y.addEventListener("click", event => { if (event.button === 0) anonymous2() });

H.addEventListener("keyup", async event => {
    if (event.key === "Enter" && c) {
        try {
            const data = await getEncryptionData(H.value, c.content);
            c.salt = data.salt;
            c.key = data.encKey;
            c.iv = data.iv;
            c.content = new TextDecoder().decode(decompress(new Uint8Array(data.key)));
            c.encrypted = false;
            c.password = H.value;
            loadFile();
        } catch (e) {
            console.warn(e);
        }
    }
});

for (const inline of document.getElementsByClassName("inline-md")) {
    let prevText = inline.innerText;
    // shift + enter is wack, so we just not gonna deal w it
    inline.addEventListener("keydown", event => { if (event.key === "Enter" && event.shiftKey) event.preventDefault() });
    inline.addEventListener("input", () => { // god save my soul
        const selection = window.getSelection();
        const range = selection.getRangeAt(0);
        range.setStart(inline, 0);
        const rstr = range.toString();
        let len = rstr.length;
        range.collapse();
        const diff = diffStrings(prevText, inline.innerText);
        const added = diff.added;
        prevText = inline.innerText;
        if (added[0] === "\n" && diff.deleted === "") { // evil hardcoded comparison hack (99% fail)
            if (len === 0) {
                inline.innerText = inline.innerText.substring(1);
                restore(inline, selection, 1);
            } else if (rstr[len - 1] === "\n") { // more evil code
                inline.innerText = inline.innerText.substring(0, len - 1) + inline.innerText.substring(len);
            }
            len += 1;
        }
        
        const parsed = parse(inline.innerText);
        if (inline.innerHTML !== parsed) {
            inline.innerHTML = parsed;
            restore(inline, selection, len);
        }
    });
}

for (const placeholder of document.querySelectorAll("[data-placeholder]")) {
    placeholder.classList.add("phtxt");
    placeholder.addEventListener("input", () => {
        if (placeholder.textContent === "\n" || !placeholder.textContent) {
            placeholder.textContent = "";
            placeholder.classList.add("phtxt");
        } else if (placeholder.classList.contains("phtxt"))
            placeholder.classList.remove("phtxt");
    });
}