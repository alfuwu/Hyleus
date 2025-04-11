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
const Q = []; // {id: null, name: "Text", parent: null, description: "Markdown text", position: 1}
const W = []; // {title: "Text", category: null, type: 0, content: "Markdown text", password: null, salt: undefined, key: undefined, iv: undefined, encrypted: false, position: 1}
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

// article types
const ARTICLE = 0; // normal article

const MENUS = [[K, C], [J, L], [G, V], [FM, null]];
const CONTENTS = [N, B, I, D];
const NAV_BUTTONS = [AR, /*BT,*/ MP];
const CONTEXT_MENUS = [HC, HFE, HFR];

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
    if (!encrypted) { // make sure that the data is decryptable
        const text = decompress(b64ToArr(arrToB64(ret))).slice(21);
        try {
            if (password)
                await getEncryptionData(password, text);
            else if (key && iv)
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
        const categoryPath = item.category ? categories[item.category].path : 'data';
        if (!(`${categoryPath}/${item.title}`.substring(5) in X))
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
        if (!(id in X))
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
    if (Object.keys(files).length === 0) {
        console.warn("Commit is empty; aborting");
        return; // don't create empty commits
    }
    const repo = 'alfuwu/Hyleus';
    const blobs = [];
    for (const path in files) {
        const resp = await fetch(`https://api.github.com/repos/${repo}/git/blobs`, {
            method: 'POST',
            headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json', 'accept': 'application/vnd.github+json' },
            body: JSON.stringify({ content: arrToB64(new Uint8Array(files[path])), encoding: "base64" })
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
    return new Uint8Array(atob(b64).map(c => c.charCodeAt(0)));
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
    ele.classList.remove("hidden");
    ele.style.left = event.pageX + "px";
    ele.style.top = event.pageY  + "px";
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
                B.innerHTML = permParse(c.content);
            }
        }
    }
}

function createTreeItem(text, dat, children = null) {
    const obj = document.createElement("button");
    obj.classList.add("hflex", "left", "fold");
    const ico = document.createElement("img");
    ico.classList.add("smol", "inv", "ico", "padr");
    ico.src = children ? "folder.svg" : "article.svg";
    obj.appendChild(ico);
    obj.appendChild(document.createTextNode(text));
    if (children) {
        obj.addEventListener("click", event => {
            if (event.button === 0)
                children.classList.toggle("hidden");
        });
        obj.addEventListener("contextmenu", event => { if (a) { d = dat; showContextMenu(HFR, event) } });
    } else {
        dat.obj = obj;
        obj.addEventListener("click", event => {
            if (event.button === 0) {
                if (c)
                    c.obj.classList.remove("selected");
                c = c === dat ? null : dat;
                if (c)
                    obj.classList.add("selected");
                loadFile();
            }
        });
        obj.addEventListener("contextmenu", event => { if (a) { d = dat; showContextMenu(HFE, event) } });
        if (c === dat)
            obj.classList.add("selected");
    }
    return obj;
}

function handleTreeItem(fof, categoryMap, iter=1) {
    if (fof.id) { // folder
        const children = document.createElement("div");
        if (fof.id in categoryMap) {
            children.classList.add("big", "padl", "hidden");
            for (const child of categoryMap[fof.id].sort((i1, i2) => i1.id && !i2.id ? -1 : i2.id && !i1.id ? 1 : i1.position !== i2.position ? i1.position - i2.position : i1.id && i2.id ? i1.name.localeCompare(i2.name) : i1.title.localeCompare(i2.title))) {
                const item = handleTreeItem(child, categoryMap, iter+1);
                if (item instanceof Array) {
                    children.appendChild(item[0]);
                    children.appendChild(item[1]);
                } else {
                    children.appendChild(item);
                }
            }
        }
        return [createTreeItem(fof.name, fof, children), children];
    }
    return createTreeItem(fof.title, fof);
}

function constructTree() {
    T.innerHTML = ``; // remove all children
    const categoryMap = W.reduce((acc, item) => {
        if (!acc[item.category])
            acc[item.category] = [];
        acc[item.category].push(item);
        return acc;
    }, {});
    Q.forEach(item => {
        if (item.parent) {
            if (!categoryMap[item.parent])
                categoryMap[item.parent] = [];
            categoryMap[item.parent].unshift(item);
        }
    });
    for (const folder of Q.sort((i1, i2) => i1.position !== i2.position ? i1.position - i2.position : i1.name.localeCompare(i2.name))) {
        if (!folder.parent) {
            const item = handleTreeItem(folder, categoryMap);
            if (item) {
                T.appendChild(item[0]);
                T.appendChild(item[1]);
            }
        }
    }
    for (const file of W.sort((i1, i2) => i1.position !== i2.position ? i1.position - i2.position : i1.title.localeCompare(i2.title)))
        if (!file.category)
            T.appendChild(handleTreeItem(file, undefined));
}

function constructCategoriesList() {
    for (const child of Q) {
        const opt = document.createElement("option");
        opt.value = formatFileName(child);
        opt.value = opt.value.substring(0, opt.value.length - 1);
        opt.textContent = child.id;
        CA.appendChild(opt);
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
        X.clear();
        await commitToGitHub(files, a);
        console.log("COMMITED");
    }
}

function parse(text) {
    let md = text
        .replace(/</gm, "&lt;")
        .replace(/^(#{1,6}) (.+)$/gm, (_, header, content) => { return `<span class="h${header.length}"><span class="mds">${header}</span> ${content}</span>`; })
        .replace(/^-# (.+)$/gm, '<span class="st"><span class="mds"><b>-#</b></span> $1</span>')
        .replace(/~~(.+?[^\\])~~/gm, '<span class="mds">~~</span><s>$1</s><span class="mds">~~</span>') // strikethrough
        .replace(/(^|[^_\\])__([^_]+?[^\\_])__($|[^_])/gm, '$1<span class="mds">__</span><u>$2</u><span class="mds">__</span>$3') // underlined
        .replace(/(^|[^_\\])_([^_]+?[^\\_])_($|[^_])/gm, '$1<span class="mds">_</span><i>$2</i><span class="mds">_</span>$3') // italic text
        .replace(/(^|[^*\\])\*\*\*([^*]+?[^\\*])\*\*\*($|[^*])/gm, '$1<span class="mds">***</span><b><i>$2</i></b><span class="mds">***</span>$3') // italic bold text
        .replace(/(^|[^*\\])\*\*([^*]+?[^\\*])\*\*($|[^*])/gm, '$1<span class="mds">**</span><b>$2</b><span class="mds">**</span>$3') // bold text
        .replace(/(^|[^*\\])\*([^*]+?[^\\*])\*($|[^*])/gm, '$1<span class="mds">*</span><i>$2</i><span class="mds">*</span>$3'); // italic text
    for (const file of W)
        md = md.replaceAll(`@${file.title}`, `<a data-text="@${file.title}"><span class="mds">@</span>${file.title}</a>`);
    return md;
}

function permParse(text) {
    let md = text
        .replace(/</gm, "&lt;")
        .replace(/^(#{1,6}) (.+)$/gm, (_, header, content) => { return `<span class="h${header.length}" id="${content.replaceAll(" ", "-").toLowerCase()}">${content}</span>`; })
        .replace(/^-# (.+)$/gm, '<span class="st">$1</span>')
        .replace(/~~(.+?[^\\])~~/gm, '<s>$1</s>') // strikethrough
        .replace(/(^|[^_\\])__([^_]+?[^\\_])__($|[^_])/gm, '$1<u>$2</u>$3') // underlined
        .replace(/(^|[^_\\])_([^_]+?[^\\_])_($|[^_])/gm, '$1<i>$2</i>$3') // italic text
        .replace(/(^|[^*\\])\*\*\*([^*]+?[^\\*])\*\*\*($|[^*])/gm, '$1<b><i>$2</i></b>$3') // italic bold text
        .replace(/(^|[^*\\])\*\*([^*]+?[^\\*])\*\*($|[^*])/gm, '$1<b>$2</b>$3') // bold text
        .replace(/(^|[^*\\])\*([^*]+?[^\\*])\*($|[^*])/gm, '$1<i>$2</i>$3'); // italic text
    for (let i = 0; i < W.length; i++)
        md = md.replaceAll(`@${W[i].title}`, `<a onclick="W[${i}].obj.click();" data-text="${W[i].title}">${W[i].title}</a>`);
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
    return W.findIndex(v => v.title === AN.value && v.category === (AC.value || null));
}

function updateAD() {
    if (findExisting() !== -1) {
        if (AD.textContent !== "Edit")
            AD.textContent = "Edit";
    } else if (AD.textContent !== "Create")
        AD.textContent = "Create"
}

function formatFileName(file, ret = "") {
    return !file ? ret : file.id ? formatFileName(file.parent ? Q.find(v => v.id === file.parent) : null, file.name + "/" + ret) : formatFileName(file.category ? Q.find(v => v.id === file.category) : null, file.title);
}

function showFolderMenu() {
    M.classList.remove("hidden");
    F.classList.remove("h");
    FM.classList.remove("hidden", "h");
    opacitate(F, 0, 0.5);
    opacitate(FM, 0, 1);
}

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
    constructTree();
    constructCategoriesList(); // important!! do this after constructTree, since constructTree sorts all categories
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
AD.addEventListener("click", event => {
    if (event.button === 0 && AN.value) {
        const file = {
            title: AN.value,
            category: AC.value || null,
            type: 0,
            content: AT.innerText,
            password: UP.checked ? guh : AP.value || null,
            salt: undefined, key: undefined, iv: undefined,
            encrypted: false,
            position: 1
        };
        const existing = findExisting();
        if (existing !== -1)
            W[existing] = file;
        else
            W.push(file);
        X.add(formatFileName(file));
        showContent(c ? B : N);
        AN.value = "";
        AC.value = "";
        AT.innerText = "";
        AP.value = "";
        AN.classList.remove("warn");
        if (UP.checked)
            UP.click();
        constructTree();
    } else if (!AN.value) {
        AN.classList.add("warn");
    }
});

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