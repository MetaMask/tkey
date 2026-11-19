import { ShareStore } from "@tkey/common-types";

import WebStorageError from "./errors";
import { getWindow } from "./utils";

// Web Specific declarations
const requestedBytes = 1024 * 1024 * 10; // 10MB

declare global {
  interface Navigator {
    webkitPersistentStorage: {
      requestQuota: (a: number, b: (grantedBytes: number) => void, c: (reason: string) => void) => unknown;
    };
  }
}

function download(filename: string, text: string): void {
  const element = document.createElement("a");
  element.setAttribute("href", `data:application/json;charset=utf-8,${encodeURIComponent(text)}`);
  element.setAttribute("download", filename);
  element.style.display = "none";
  document.body.appendChild(element);
  element.click();
  document.body.removeChild(element);
}
async function requestQuota(): Promise<number> {
  return new Promise((resolve, reject) => {
    navigator.webkitPersistentStorage.requestQuota(requestedBytes, resolve, reject);
  });
}
function hasFileSystemApi(win: Window): boolean {
  const legacy = win as Window & { requestFileSystem?: unknown; webkitRequestFileSystem?: unknown };
  return typeof legacy.requestFileSystem === "function" || typeof legacy.webkitRequestFileSystem === "function";
}
async function browserRequestFileSystem(grantedBytes: number): Promise<FileSystem> {
  return new Promise((resolve, reject) => {
    const win = getWindow();
    win.requestFileSystem = win.requestFileSystem || win.webkitRequestFileSystem;
    win.requestFileSystem(win.PERSISTENT, grantedBytes, resolve, reject);
  });
}
async function getFile(fs: FileSystem, path: string, create: boolean): Promise<FileEntry> {
  return new Promise<FileEntry>((resolve, reject) => {
    fs.root.getFile(path, { create }, (data) => resolve(data as FileEntry), reject);
  });
}
async function readFile(fileEntry: FileEntry): Promise<File> {
  return new Promise((resolve, reject) => {
    fileEntry.file(resolve, reject);
  });
}

export const getShareFromFileStorage = async (key: string): Promise<ShareStore> => {
  const win = getWindow();
  win.requestFileSystem = win.requestFileSystem || win.webkitRequestFileSystem;
  if (hasFileSystemApi(win)) {
    const fs = await browserRequestFileSystem(requestedBytes);

    const fileEntry = await getFile(fs, key, false);
    const file = await readFile(fileEntry);
    const fileStr = await file.text();
    if (!fileStr) {
      throw WebStorageError.shareUnavailableInFileStorage();
    }
    return ShareStore.fromJSON(JSON.parse(fileStr));
  }
  throw WebStorageError.fileStorageUnavailable();
};

export const storeShareOnFileStorage = async (share: ShareStore, key: string): Promise<void> => {
  // if we're on chrome (thus window.requestFileSystem exists) we use it
  const fileName = `${key}.json`;
  const fileStr = JSON.stringify(share);
  const win = getWindow();
  win.requestFileSystem = win.requestFileSystem || win.webkitRequestFileSystem;
  if (hasFileSystemApi(win)) {
    const grantedBytes = await requestQuota();
    const fs = await browserRequestFileSystem(grantedBytes);
    const fileEntry = await getFile(fs, key, true);
    await new Promise((resolve, reject) => {
      fileEntry.createWriter((fileWriter) => {
        fileWriter.onwriteend = resolve;
        fileWriter.onerror = reject;
        const bb = new Blob([fileStr], { type: "application/json" });
        fileWriter.write(bb);
      }, reject);
    });
  } else {
    // we make the user download a file
    download(fileName, fileStr);
  }
};

export const canAccessFileStorage = async (): Promise<PermissionStatus> => navigator.permissions.query({ name: "persistent-storage" });
