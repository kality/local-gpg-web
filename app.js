(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let revocationCertificate = '';
  let toastTimer = null;

  function setStatus(element, message, type = '') {
    element.textContent = message;
    element.className = `status${element.classList.contains('block') ? ' block' : ''}${type ? ` ${type}` : ''}`;
  }

  function showToast(message) {
    const toast = $('toast');
    toast.textContent = message;
    toast.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add('hidden'), 2300);
  }

  function humanSize(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) return '';
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value.toFixed(unit === 0 ? 0 : value < 10 ? 2 : 1)} ${units[unit]}`;
  }

  function safeBaseName(value, fallback = 'openpgp') {
    const cleaned = String(value || '')
      .trim()
      .replace(/[\\/:*?"<>|\u0000-\u001F]/g, '-')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^[-.]+|[-.]+$/g, '')
      .slice(0, 80);
    return cleaned || fallback;
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = safeBaseName(filename, 'download');
    link.rel = 'noopener';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  function downloadText(text, filename, mime = 'text/plain;charset=utf-8') {
    if (!text) throw new Error('没有可下载的内容');
    downloadBlob(new Blob([text], { type: mime }), filename);
  }

  async function copyText(text) {
    if (!text) throw new Error('没有可复制的内容');
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    if (!ok) throw new Error('浏览器未允许复制，请手动选择文本复制');
  }

  async function readTextFile(file) {
    if (!file) throw new Error('未选择文件');
    return await file.text();
  }

  function formatFingerprint(fingerprint) {
    return (fingerprint || '').toUpperCase().replace(/\s+/g, '').match(/.{1,4}/g)?.join(' ') || '';
  }

  async function parsePublicKey(armored) {
    if (!armored.trim()) throw new Error('请提供公钥');
    return await openpgp.readKey({ armoredKey: armored.trim() });
  }

  async function parsePrivateKey(armored, passphrase) {
    if (!armored.trim()) throw new Error('请提供私钥');
    let privateKey = await openpgp.readPrivateKey({ armoredKey: armored.trim() });
    if (typeof privateKey.isDecrypted === 'function' && privateKey.isDecrypted()) return privateKey;
    if (!passphrase) throw new Error('该私钥已加密，请输入私钥口令');
    privateKey = await openpgp.decryptKey({ privateKey, passphrase });
    return privateKey;
  }

  async function toUint8Array(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (typeof data === 'string') return encoder.encode(data);
    if (data && typeof data.getReader === 'function') {
      const reader = data.getReader();
      const chunks = [];
      let total = 0;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
        chunks.push(chunk);
        total += chunk.length;
      }
      const output = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        output.set(chunk, offset);
        offset += chunk.length;
      }
      return output;
    }
    throw new Error('无法识别解密后的数据格式');
  }


  const LARGE_FILE_WARNING_BYTES = 200 * 1024 * 1024;
  const STREAM_DECRYPT_CONFIG = Object.freeze({ allowUnauthenticatedStream: true });

  function isReadableStream(value) {
    return Boolean(value && typeof value.getReader === 'function');
  }

  function supportsDirectFileSave() {
    return Boolean(
      window.isSecureContext &&
      typeof window.showSaveFilePicker === 'function' &&
      typeof File !== 'undefined' &&
      typeof File.prototype.stream === 'function' &&
      typeof TransformStream !== 'undefined'
    );
  }

  function isAbortError(error) {
    return error?.name === 'AbortError';
  }

  function fileSaveTypes(filename, mime) {
    const match = /(?:\.([^.]+))?$/.exec(filename || '');
    const extension = match?.[1] ? `.${match[1].toLowerCase()}` : '';
    if (!extension) return undefined;
    return [{
      description: extension === '.asc' ? 'ASCII Armor OpenPGP 文件' : 'OpenPGP/二进制文件',
      accept: { [mime || 'application/octet-stream']: [extension] }
    }];
  }

  async function requestSaveHandle(filename, mime = 'application/octet-stream') {
    return await window.showSaveFilePicker({
      suggestedName: safeBaseName(filename, 'output'),
      types: fileSaveTypes(filename, mime),
      excludeAcceptAllOption: false
    });
  }

  function createProgressStream(file, onProgress) {
    let processed = 0;
    let lastUpdate = 0;
    return file.stream().pipeThrough(new TransformStream({
      transform(chunk, controller) {
        processed += chunk.byteLength || chunk.length || 0;
        const now = performance.now();
        if (now - lastUpdate >= 180 || processed >= file.size) {
          lastUpdate = now;
          onProgress(processed, file.size);
        }
        controller.enqueue(chunk);
      },
      flush() {
        onProgress(file.size, file.size);
      }
    }));
  }

  function bytesToUtf8Stream(byteStream) {
    const streamDecoder = new TextDecoder('utf-8');
    return byteStream.pipeThrough(new TransformStream({
      transform(chunk, controller) {
        const text = streamDecoder.decode(chunk, { stream: true });
        if (text) controller.enqueue(text);
      },
      flush(controller) {
        const text = streamDecoder.decode();
        if (text) controller.enqueue(text);
      }
    }));
  }

  function progressText(action, file, processed, total) {
    const percent = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;
    return `${action} ${file.name}：已读取 ${humanSize(processed)} / ${humanSize(total)}（${percent}%）`;
  }

  async function pipeOutputToFile(output, handle) {
    const writable = await handle.createWritable();
    try {
      if (isReadableStream(output)) {
        await output.pipeTo(writable);
      } else if (output && typeof output[Symbol.asyncIterator] === 'function') {
        for await (const chunk of output) await writable.write(chunk);
        await writable.close();
      } else {
        await writable.write(output);
        await writable.close();
      }
    } catch (error) {
      try {
        await writable.abort(error);
      } catch (_) {
        // pipeTo 通常已经自动中止临时文件，此处仅作为兜底。
      }
      throw error;
    }
  }

  async function isArmoredFile(file) {
    const head = await file.slice(0, 160).text();
    return head.includes('-----BEGIN PGP MESSAGE-----');
  }

  function updateFileModeNotice() {
    const notice = $('fileModeNotice');
    if (!notice) return;
    const direct = supportsDirectFileSave();
    notice.className = direct ? 'notice info' : 'notice warning';
    notice.innerHTML = direct
      ? '<strong>大文件流式模式已启用。</strong> 文件会边读取、边加解密、边写入你选择的位置，不会整份载入内存。'
      : '<strong>当前浏览器使用兼容模式。</strong> 文件仍不会上传服务器，但结果需要先聚合到浏览器内存再下载；大文件请改用支持“另存为”接口的 HTTPS/localhost Chrome、Edge 或其他兼容浏览器。';
    $('encryptFileBtn').textContent = direct ? '加密并保存' : '加密并下载';
    $('decryptFileBtn').textContent = direct ? '解密并保存' : '解密并下载';
  }

  function setBusy(button, busy, busyText = '处理中…') {
    if (!button.dataset.originalText) button.dataset.originalText = button.textContent;
    button.disabled = busy;
    button.textContent = busy ? busyText : button.dataset.originalText;
  }

  async function generateKeys() {
    const button = $('generateKeyBtn');
    const status = $('keyStatus');
    const name = $('keyName').value.trim();
    const email = $('keyEmail').value.trim();
    const passphrase = $('keyPassphrase').value;
    const confirm = $('keyPassphraseConfirm').value;
    const algorithm = $('keyAlgorithm').value;
    const expiryDays = Number($('keyExpiryDays').value || 0);

    if (!name) throw new Error('请输入名称或昵称');
    if (passphrase.length < 10) throw new Error('私钥口令至少需要 10 个字符');
    if (passphrase !== confirm) throw new Error('两次输入的口令不一致');
    if (!Number.isInteger(expiryDays) || expiryDays < 0 || expiryDays > 36500) throw new Error('有效期应为 0–36500 天的整数');

    const userID = email ? { name, email } : { name };
    const options = {
      userIDs: [userID],
      passphrase,
      format: 'armored'
    };
    if (expiryDays > 0) options.keyExpirationTime = expiryDays * 86400;
    if (algorithm === 'curve25519') {
      options.type = 'ecc';
      options.curve = 'curve25519';
    } else {
      options.type = 'rsa';
      options.rsaBits = algorithm === 'rsa4096' ? 4096 : 3072;
    }

    setBusy(button, true, algorithm === 'rsa4096' ? '生成中，RSA 4096 可能较慢…' : '生成中…');
    setStatus(status, '正在浏览器本地生成密钥，请勿关闭页面…');
    try {
      const result = await openpgp.generateKey(options);
      $('publicKeyText').value = result.publicKey;
      $('privateKeyText').value = result.privateKey;
      revocationCertificate = result.revocationCertificate || '';
      $('downloadRevocationBtn').disabled = !revocationCertificate;
      const key = await openpgp.readKey({ armoredKey: result.publicKey });
      $('keyFingerprint').textContent = formatFingerprint(key.getFingerprint());
      $('fingerprintBox').classList.remove('hidden');
      setStatus(status, '密钥对已生成。请立即下载私钥和撤销证书并离线备份。', 'success');
      showToast('密钥生成完成');
    } finally {
      setBusy(button, false);
    }
  }

  async function inspectManagedKey() {
    const publicArmored = $('publicKeyText').value.trim();
    const privateArmored = $('privateKeyText').value.trim();
    if (!publicArmored && !privateArmored) throw new Error('请先粘贴或导入公钥/私钥');
    let fingerprint = '';
    if (publicArmored) {
      const publicKey = await openpgp.readKey({ armoredKey: publicArmored });
      fingerprint = publicKey.getFingerprint();
    } else {
      const privateKey = await openpgp.readPrivateKey({ armoredKey: privateArmored });
      fingerprint = privateKey.getFingerprint();
    }
    $('keyFingerprint').textContent = formatFingerprint(fingerprint);
    $('fingerprintBox').classList.remove('hidden');
    showToast('密钥格式有效');
  }

  async function encryptText() {
    const button = $('encryptTextBtn');
    const status = $('textStatus');
    const text = $('plainTextInput').value;
    if (!text) throw new Error('请输入待加密文字');
    setBusy(button, true);
    setStatus(status, '正在加密文字…');
    try {
      const publicKey = await parsePublicKey($('textEncryptPublicKey').value);
      const message = await openpgp.createMessage({ text });
      const encrypted = await openpgp.encrypt({ message, encryptionKeys: publicKey, format: 'armored' });
      $('encryptedTextOutput').value = encrypted;
      setStatus(status, '文字已加密。', 'success');
    } finally {
      setBusy(button, false);
    }
  }

  async function decryptText() {
    const button = $('decryptTextBtn');
    const status = $('textStatus');
    const armoredMessage = $('encryptedTextInput').value.trim();
    if (!armoredMessage) throw new Error('请输入 PGP 加密文字');
    setBusy(button, true);
    setStatus(status, '正在解密文字…');
    try {
      const privateKey = await parsePrivateKey($('privateKeyText').value, $('textDecryptPassphrase').value);
      const message = await openpgp.readMessage({ armoredMessage });
      const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey, format: 'utf8' });
      $('decryptedTextOutput').value = typeof data === 'string' ? data : decoder.decode(await toUint8Array(data));
      setStatus(status, '文字已解密。', 'success');
    } finally {
      setBusy(button, false);
    }
  }

  async function encryptFileFallback(file, publicKey, armored, status) {
    if (file.size > LARGE_FILE_WARNING_BYTES) {
      setStatus(status, `兼容模式将把 ${humanSize(file.size)} 文件和结果保存在内存中，移动设备可能失败。`);
    } else {
      setStatus(status, `正在以内存兼容模式加密 ${file.name}（${humanSize(file.size)}）…`);
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    const message = await openpgp.createMessage({ binary: bytes, filename: file.name, date: new Date(file.lastModified || Date.now()) });
    const encrypted = await openpgp.encrypt({
      message,
      encryptionKeys: publicKey,
      format: armored ? 'armored' : 'binary'
    });
    if (armored) {
      downloadText(encrypted, `${file.name}.asc`, 'application/pgp-encrypted;charset=utf-8');
    } else {
      const output = await toUint8Array(encrypted);
      downloadBlob(new Blob([output], { type: 'application/octet-stream' }), `${file.name}.gpg`);
    }
  }

  async function encryptFile() {
    const button = $('encryptFileBtn');
    const status = $('fileStatus');
    const file = $('encryptFileInput').files[0];
    if (!file) throw new Error('请选择要加密的文件');
    if (!$('fileEncryptPublicKey').value.trim()) throw new Error('请提供接收方公钥');

    const armored = $('armorFileOutput').checked;
    const outputName = `${file.name}${armored ? '.asc' : '.gpg'}`;
    let saveHandle = null;

    if (supportsDirectFileSave()) {
      try {
        // 必须在点击事件的用户激活仍有效时立即打开系统“另存为”窗口。
        saveHandle = await requestSaveHandle(
          outputName,
          armored ? 'application/pgp-encrypted' : 'application/octet-stream'
        );
      } catch (error) {
        if (isAbortError(error)) {
          setStatus(status, '已取消保存。');
          return;
        }
        console.warn('直接写盘不可用，回退到兼容下载模式：', error);
        setStatus(status, '浏览器未允许直接写盘，已回退到内存兼容模式。');
      }
    }

    setBusy(button, true, '加密中…');
    try {
      const publicKey = await parsePublicKey($('fileEncryptPublicKey').value);
      if (!saveHandle) {
        await encryptFileFallback(file, publicKey, armored, status);
      } else {
        const input = createProgressStream(file, (processed, total) => {
          setStatus(status, progressText('正在加密', file, processed, total));
        });
        const message = await openpgp.createMessage({
          binary: input,
          filename: file.name,
          date: new Date(file.lastModified || Date.now())
        });
        const encrypted = await openpgp.encrypt({
          message,
          encryptionKeys: publicKey,
          format: armored ? 'armored' : 'binary'
        });
        await pipeOutputToFile(encrypted, saveHandle);
      }
      setStatus(status, `加密完成：${saveHandle?.name || outputName}`, 'success');
    } finally {
      setBusy(button, false);
      updateFileModeNotice();
    }
  }

  function looksArmored(bytes) {
    const head = decoder.decode(bytes.slice(0, Math.min(bytes.length, 100)));
    return head.includes('-----BEGIN PGP MESSAGE-----');
  }

  async function decryptFileFallback(file, privateKey, status) {
    if (file.size > LARGE_FILE_WARNING_BYTES) {
      setStatus(status, `兼容模式将把 ${humanSize(file.size)} 文件和结果保存在内存中，移动设备可能失败。`);
    } else {
      setStatus(status, `正在以内存兼容模式解密 ${file.name}（${humanSize(file.size)}）…`);
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    const message = looksArmored(bytes)
      ? await openpgp.readMessage({ armoredMessage: decoder.decode(bytes) })
      : await openpgp.readMessage({ binaryMessage: bytes });
    const result = await openpgp.decrypt({ message, decryptionKeys: privateKey, format: 'binary' });
    const output = await toUint8Array(result.data);
    const fallback = file.name.replace(/\.(gpg|pgp|asc)$/i, '') || 'decrypted-file';
    const outputName = safeBaseName(result.filename || fallback, 'decrypted-file');
    downloadBlob(new Blob([output], { type: 'application/octet-stream' }), outputName);
    return outputName;
  }

  async function decryptFile() {
    const button = $('decryptFileBtn');
    const status = $('fileStatus');
    const file = $('decryptFileInput').files[0];
    if (!file) throw new Error('请选择要解密的文件');
    if (!$('privateKeyText').value.trim()) throw new Error('请先在“密钥管理”中加载私钥');

    const fallbackName = safeBaseName(file.name.replace(/\.(gpg|pgp|asc)$/i, '') || 'decrypted-file', 'decrypted-file');
    let saveHandle = null;

    if (supportsDirectFileSave()) {
      try {
        // 解密包中的原文件名要在解析后才能知道，因此先用去掉 .gpg/.pgp/.asc 的名称建议保存。
        saveHandle = await requestSaveHandle(fallbackName, 'application/octet-stream');
      } catch (error) {
        if (isAbortError(error)) {
          setStatus(status, '已取消保存。');
          return;
        }
        console.warn('直接写盘不可用，回退到兼容下载模式：', error);
        setStatus(status, '浏览器未允许直接写盘，已回退到内存兼容模式。');
      }
    }

    setBusy(button, true, '解密中…');
    try {
      const privateKey = await parsePrivateKey($('privateKeyText').value, $('fileDecryptPassphrase').value);
      let outputName;
      if (!saveHandle) {
        outputName = await decryptFileFallback(file, privateKey, status);
      } else {
        const armored = await isArmoredFile(file);
        let input = createProgressStream(file, (processed, total) => {
          setStatus(status, progressText('正在解密', file, processed, total));
        });
        if (armored) input = bytesToUtf8Stream(input);

        const message = armored
          ? await openpgp.readMessage({ armoredMessage: input, config: STREAM_DECRYPT_CONFIG })
          : await openpgp.readMessage({ binaryMessage: input, config: STREAM_DECRYPT_CONFIG });
        const result = await openpgp.decrypt({
          message,
          decryptionKeys: privateKey,
          format: 'binary',
          config: STREAM_DECRYPT_CONFIG
        });
        outputName = saveHandle.name || safeBaseName(result.filename || fallbackName, 'decrypted-file');

        // createWritable() 先写临时文件；只有完整读取并通过 OpenPGP 完整性校验后 pipeTo 才会关闭并提交。
        // 若数据损坏或校验失败，pipeTo 会中止写入，避免留下部分明文文件。
        await pipeOutputToFile(result.data, saveHandle);
      }
      setStatus(status, `解密完成：${outputName}`, 'success');
    } finally {
      setBusy(button, false);
      updateFileModeNotice();
    }
  }

  function useManagedPublicKey(targetId) {
    const key = $('publicKeyText').value.trim();
    if (!key) throw new Error('“密钥管理”中还没有公钥');
    $(targetId).value = key;
    showToast('已填入公钥');
  }

  function ensureManagedPrivateKey() {
    if (!$('privateKeyText').value.trim()) throw new Error('“密钥管理”中还没有私钥');
    showToast('解密将使用已加载私钥');
  }

  function clearSensitiveData() {
    const ids = [
      'keyPassphrase', 'keyPassphraseConfirm', 'publicKeyText', 'privateKeyText',
      'plainTextInput', 'textEncryptPublicKey', 'encryptedTextInput', 'textDecryptPassphrase',
      'encryptedTextOutput', 'decryptedTextOutput', 'fileEncryptPublicKey', 'fileDecryptPassphrase'
    ];
    ids.forEach((id) => { $(id).value = ''; });
    $('encryptFileInput').value = '';
    $('decryptFileInput').value = '';
    $('encryptFileName').textContent = '尚未选择文件';
    $('decryptFileName').textContent = '尚未选择文件';
    revocationCertificate = '';
    $('downloadRevocationBtn').disabled = true;
    $('fingerprintBox').classList.add('hidden');
    setStatus($('keyStatus'), '');
    setStatus($('textStatus'), '');
    setStatus($('fileStatus'), '');
    showToast('页面中的敏感字段已清空');
  }

  function bindDropzone(dropzone, input, label) {
    ['dragenter', 'dragover'].forEach((eventName) => {
      dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.add('dragover');
      });
    });
    ['dragleave', 'drop'].forEach((eventName) => {
      dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.remove('dragover');
      });
    });
    dropzone.addEventListener('drop', (event) => {
      const file = event.dataTransfer?.files?.[0];
      if (!file) return;
      const transfer = new DataTransfer();
      transfer.items.add(file);
      input.files = transfer.files;
      label.textContent = `${file.name} · ${humanSize(file.size)}`;
    });
    input.addEventListener('change', () => {
      const file = input.files[0];
      label.textContent = file ? `${file.name} · ${humanSize(file.size)}` : '尚未选择文件';
    });
  }

  function wrapAction(handler, statusElement = null) {
    return async () => {
      try {
        await handler();
      } catch (error) {
        console.error(error);
        const message = error instanceof Error ? error.message : String(error);
        if (statusElement) setStatus(statusElement, message, 'error');
        showToast(message);
      }
    };
  }

  function initTabs() {
    document.querySelectorAll('.tab').forEach((tab) => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((item) => item.classList.toggle('active', item === tab));
        document.querySelectorAll('.panel').forEach((panel) => panel.classList.toggle('active', panel.dataset.panel === tab.dataset.tab));
      });
    });
  }

  function initRuntime() {
    const warning = $('runtimeWarning');
    if (!window.openpgp) {
      warning.textContent = 'OpenPGP.js 未加载。请先运行 npm install 和 npm run prepare-offline，或把 openpgp.min.js 放入 vendor 目录。';
      warning.classList.remove('hidden');
      document.querySelectorAll('button').forEach((button) => {
        if (!button.classList.contains('tab')) button.disabled = true;
      });
      return false;
    }
    if (!window.crypto?.subtle) {
      warning.textContent = '当前浏览器缺少 Web Crypto API，无法安全运行。请使用最新版 Safari、Chrome、Edge 或 Firefox。';
      warning.classList.remove('hidden');
      return false;
    }
    if (location.protocol === 'file:') {
      warning.textContent = '当前以本地文件方式运行。加解密可以正常使用；“复制到剪贴板”和 PWA 安装可能受浏览器限制。';
      warning.classList.remove('hidden');
    }
    return true;
  }

  function initEvents() {
    $('generateKeyBtn').addEventListener('click', wrapAction(generateKeys, $('keyStatus')));
    $('inspectKeysBtn').addEventListener('click', wrapAction(inspectManagedKey, $('keyStatus')));
    $('downloadPublicKeyBtn').addEventListener('click', wrapAction(async () => {
      const name = safeBaseName($('keyEmail').value || $('keyName').value, 'public-key');
      downloadText($('publicKeyText').value, `${name}-public.asc`, 'application/pgp-keys;charset=utf-8');
    }));
    $('downloadPrivateKeyBtn').addEventListener('click', wrapAction(async () => {
      const name = safeBaseName($('keyEmail').value || $('keyName').value, 'private-key');
      downloadText($('privateKeyText').value, `${name}-private.asc`, 'application/pgp-keys;charset=utf-8');
    }));
    $('downloadRevocationBtn').addEventListener('click', wrapAction(async () => {
      const name = safeBaseName($('keyEmail').value || $('keyName').value, 'key');
      downloadText(revocationCertificate, `${name}-revocation.asc`, 'application/pgp-signature;charset=utf-8');
    }));

    $('publicKeyFileInput').addEventListener('change', wrapAction(async () => {
      $('publicKeyText').value = await readTextFile($('publicKeyFileInput').files[0]);
      await inspectManagedKey();
    }, $('keyStatus')));
    $('privateKeyFileInput').addEventListener('change', wrapAction(async () => {
      $('privateKeyText').value = await readTextFile($('privateKeyFileInput').files[0]);
      await inspectManagedKey();
    }, $('keyStatus')));

    $('encryptTextBtn').addEventListener('click', wrapAction(encryptText, $('textStatus')));
    $('decryptTextBtn').addEventListener('click', wrapAction(decryptText, $('textStatus')));
    $('useManagedPublicKeyBtn').addEventListener('click', wrapAction(async () => useManagedPublicKey('textEncryptPublicKey')));
    $('useManagedPrivateKeyBtn').addEventListener('click', wrapAction(async () => ensureManagedPrivateKey()));
    $('downloadEncryptedTextBtn').addEventListener('click', wrapAction(async () => downloadText($('encryptedTextOutput').value, 'encrypted-message.asc', 'application/pgp-encrypted;charset=utf-8')));
    $('downloadDecryptedTextBtn').addEventListener('click', wrapAction(async () => downloadText($('decryptedTextOutput').value, 'decrypted-message.txt')));

    $('encryptFileBtn').addEventListener('click', wrapAction(encryptFile, $('fileStatus')));
    $('decryptFileBtn').addEventListener('click', wrapAction(decryptFile, $('fileStatus')));
    $('useManagedPublicKeyFileBtn').addEventListener('click', wrapAction(async () => useManagedPublicKey('fileEncryptPublicKey')));
    $('useManagedPrivateKeyFileBtn').addEventListener('click', wrapAction(async () => ensureManagedPrivateKey()));

    document.querySelectorAll('[data-copy-target]').forEach((button) => {
      button.addEventListener('click', wrapAction(async () => {
        await copyText($(button.dataset.copyTarget).value);
        showToast('已复制');
      }));
    });

    $('clearAllBtn').addEventListener('click', clearSensitiveData);
    bindDropzone($('encryptDropzone'), $('encryptFileInput'), $('encryptFileName'));
    bindDropzone($('decryptDropzone'), $('decryptFileInput'), $('decryptFileName'));
    updateFileModeNotice();
  }

  function registerServiceWorker() {
    if ('serviceWorker' in navigator && ['http:', 'https:'].includes(location.protocol)) {
      navigator.serviceWorker.register('./sw.js').catch((error) => console.warn('Service worker registration failed:', error));
    }
  }

  initTabs();
  const ready = initRuntime();
  if (ready) initEvents();
  registerServiceWorker();
})();
