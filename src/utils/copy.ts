import { createSignal } from "solid-js";

export const [copyNotice, setCopyNotice] = createSignal(false);

export const addToClipboard = (text: string) => {
  navigator.clipboard.writeText(text);
  setCopyNotice(true);
  setTimeout(() => setCopyNotice(false), 3000);
};
