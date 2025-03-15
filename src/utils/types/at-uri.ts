const DID_RE = /^did:([a-z]+):([a-zA-Z0-9._:%\-]*[a-zA-Z0-9._\-])$/;

const NSID_RE =
  /^[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?:\.[a-zA-Z](?:[a-zA-Z0-9]{0,62})?)$/;

const RECORD_KEY_RE = /(?!\.{1,2}$)[a-zA-Z0-9_~.:-]{1,512}/;

const ATURI_RE =
  /^at:\/\/([a-zA-Z0-9._:%-]+)(?:\/([a-zA-Z0-9-.]+)(?:\/([a-zA-Z0-9._~:@!$&%')(*+,;=-]+)))(?:#(\/[a-zA-Z0-9._~:@!$&%')(*+,;=\-[\]/\\]*))?$/;

type Did<TMethod extends string = string> = `did:${TMethod}:${string}`;

type Nsid = `${string}.${string}.${string}`;

export interface AddressedAtUri {
  repo: Did;
  collection: Nsid;
  rkey: string;
  fragment: string | undefined;
}

const isDid = (input: string): input is Did => {
  return input.length >= 7 && input.length <= 2048 && DID_RE.test(input);
};

const isNsid = (str: string): str is Nsid => {
  return str.length >= 5 && str.length <= 317 && NSID_RE.test(str);
};

const isRecordKey = (input: string) => {
  return input.length >= 1 && input.length <= 512 && RECORD_KEY_RE.test(input);
};

export const parseAddressedAtUri = (str: string): AddressedAtUri => {
  const match = ATURI_RE.exec(str);
  assert(match !== null, `invalid at-uri: ${str}`);

  const [, repo, collection, rkey, fragment] = match;
  assert(isDid(repo), `invalid repo in at-uri: ${repo}`);
  assert(isNsid(collection), `invalid collection in at-uri: ${collection}`);
  assert(isRecordKey(rkey), `invalid rkey in at-uri: ${rkey}`);

  return {
    repo,
    collection,
    rkey,
    fragment,
  };
};

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}
