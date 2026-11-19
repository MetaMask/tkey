import { ShareStore } from "@tkey/common-types";

import WebStorageError from "./errors";
import { getWindow } from "./utils";

function storageAvailable(type: string): boolean {
  const win = getWindow();
  let storage: Storage | undefined;
  try {
    storage = win[type as "sessionStorage" | "localStorage"];
    const x = "__storage_test__";
    storage.setItem(x, x);
    storage.removeItem(x);
    return true;
  } catch (e) {
    return (
      e instanceof DOMException &&
      // everything except Firefox
      (e.code === 22 ||
        // Firefox
        e.code === 1014 ||
        // test name field too, because code might not be present
        // everything except Firefox
        e.name === "QuotaExceededError" ||
        // Firefox
        e.name === "NS_ERROR_DOM_QUOTA_REACHED") &&
      // acknowledge QuotaExceededError only if there's something already stored
      storage !== undefined &&
      storage.length !== 0
    );
  }
}

export const storeShareOnLocalStorage = async (share: ShareStore, key: string): Promise<void> => {
  const fileStr = JSON.stringify(share);
  if (!storageAvailable("localStorage")) {
    throw WebStorageError.localStorageUnavailable();
  }
  const win = getWindow();
  win.localStorage.setItem(key, fileStr);
};

export const getShareFromLocalStorage = async (key: string): Promise<ShareStore> => {
  if (!storageAvailable("localStorage")) {
    throw WebStorageError.localStorageUnavailable();
  }
  const win = getWindow();
  const foundFile = win.localStorage.getItem(key);
  if (!foundFile) throw WebStorageError.shareUnavailableInLocalStorage();
  return ShareStore.fromJSON(JSON.parse(foundFile));
};
