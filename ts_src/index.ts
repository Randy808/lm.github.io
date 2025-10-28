import { ECPairFactory, ECPairInterface } from "ecpair";
import * as ecc from "@bitcoin-js/tiny-secp256k1-asmjs";
import * as liquidjs from "liquidjs-lib";
import { Psbt } from "liquidjs-lib/src/psbt";
import { sha256 } from "@noble/hashes/sha2";
import { secp256k1 } from "@noble/curves/secp256k1";
import { Fn } from "./utils";
import {
  getDecryptedRingSignatureRangeProof,
  getDecryptedRingSignatureRangeProofFromOutput,
  modifyRangeProof,
} from "./modify-tx-with-rangeproof";
import { getMessageFromDecryptedSignature } from "./message";
import { getRandomValues } from "crypto";

const ECPair = ECPairFactory(ecc);
const NETWORK = liquidjs.networks.testnet;
const address = liquidjs.address;
let allUtxos: any;
const MESSAGE_PREFIX = "lm";
const OUTPUT_INDEX = 0;
const HOST = "localhost:3001"; ///blockstream.info/liquid/api
const EXPLORER_URL = "http://localhost:5001";

// Interface for UTXO data from block explorer
interface UTXO {
  txid: string;
  vout: number;
  value: number; // in satoshis
  status: {
    confirmed: boolean;
    block_height?: number;
    block_hash?: string;
    block_time?: number;
  };
  asset?: string; // for Liquid network
  assetcommitment?: string;
  valuecommitment?: string;
}

// Fetch all UTXOs for a given address
async function getUTXOs(address: string): Promise<UTXO[]> {
  const explorerUrl = `${HOST}/address/${address}/utxo`;

  try {
    const response = await fetch(explorerUrl);

    if (!response.ok) {
      throw new Error(`Failed to fetch UTXOs: ${response.statusText}`);
    }

    const utxos: UTXO[] = await response.json();
    allUtxos = utxos;
    return utxos;
  } catch (error) {
    console.error("Error fetching UTXOs:", error);
    throw error;
  }
}

// Select UTXOs to meet target value using greedy algorithm
function selectUTXOs(utxos: UTXO[], targetValue: number): UTXO[] {
  // Filter only confirmed UTXOs and sort by value (largest first)
  const sortedUTXOs = utxos
    .filter((utxo) => utxo.status.confirmed)
    .sort((a, b) => b.value - a.value);

  const selectedUTXOs: UTXO[] = [];
  let totalValue = 0;

  // Greedy selection: pick largest UTXOs first
  for (const utxo of sortedUTXOs) {
    if (totalValue >= targetValue) {
      break;
    }

    selectedUTXOs.push(utxo);
    totalValue += utxo.value;
  }

  // Check if we have enough
  if (totalValue < targetValue) {
    throw new Error(
      `Insufficient funds: need ${targetValue} satoshis, but only have ${totalValue} satoshis`
    );
  }

  return selectedUTXOs;
}

// Example usage:
// const utxos = await getUTXOs('your-liquid-address');
// const selected = selectUTXOs(utxos, 100000); // select UTXOs for 100k sats

function initializeKeypairs() {
  if (!localStorage.getItem("privateKey")) {
    const keypair = ECPair.makeRandom();
    localStorage.setItem("privateKey", keypair.privateKey!.toString("hex"));
  }

  if (!localStorage.getItem("blindingKey")) {
    const blindingKeyPair = ECPair.makeRandom();
    localStorage.setItem(
      "blindingKey",
      blindingKeyPair.privateKey!.toString("hex")
    );
  }
}

initializeKeypairs();

function getAddress() {
  return getPayment().address;
}

function getPayment() {
  let privateKeyHex = localStorage.getItem("privateKey");
  let keypair = ECPair.fromPrivateKey(Buffer.from(privateKeyHex!, "hex"));
  const payment = liquidjs.payments.p2wpkh({
    pubkey: keypair.publicKey,
    network: NETWORK,
  });

  // prompt(payment.address);
  return payment;
}

function getKeypair() {
  let privateKeyhex = Buffer.from(localStorage.getItem("privateKey")!, "hex");
  return ECPair.fromPrivateKey(privateKeyhex);
}

function getBlindingKey(): ECPairInterface {
  let blindingKeyHex = Buffer.from(localStorage.getItem("blindingKey")!, "hex");
  return ECPair.fromPrivateKey(blindingKeyHex);
}

function getConfidentialAddress() {
  let confidentialAddress = liquidjs.address.toConfidential(
    getPayment().address!,
    getBlindingKey().publicKey
  );

  // prompt(confidentialAddress);
  return confidentialAddress;
}

async function createBlindedTransaction(
  unconfidentialAddress: string,
  amount: number
): Promise<Psbt> {
  const psbt = new Psbt({
    network: NETWORK,
  });

  let payment = getPayment();
  console.log(payment.address);
  let utxos = await getUTXOs(payment.address);
  let selectedUtxos = await selectUTXOs(utxos, 5000);
  let assetBuffer = Buffer.from(
    NETWORK.assetHash + "01",
    "hex"
  ).reverse();

  let TOTAL_VALUE = 0;

  for (let utxo of selectedUtxos) {
    if (utxo.valuecommitment) {
      //TODO: Handle blinded inputs
      continue;
    }

    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: {
        asset: assetBuffer,
        script: payment.output!,
        value: liquidjs.confidential.satoshiToConfidentialValue(utxo.value),
        nonce: Buffer.alloc(1, 0),
      },
    });

    TOTAL_VALUE += utxo.value;
  }

  psbt.addOutput({
    script: address.toOutputScript(unconfidentialAddress, NETWORK),
    value: liquidjs.confidential.satoshiToConfidentialValue(amount),
    asset: assetBuffer, // L-BTC asset
    nonce: Buffer.alloc(1, 0),
  });

  const FEE = 150;

  psbt.addOutput({
    script: payment.output!,
    value: liquidjs.confidential.satoshiToConfidentialValue(
      TOTAL_VALUE - amount - FEE
    ),
    asset: Buffer.from(NETWORK.assetHash + "01", "hex").reverse(), // L-BTC asset
    nonce: Buffer.alloc(1, 0),
  });

  psbt.addOutput({
    script: Buffer.alloc(0),
    value: liquidjs.confidential.satoshiToConfidentialValue(FEE),
    asset: Buffer.from(NETWORK.assetHash + "01", "hex").reverse(), // L-BTC asset
    nonce: Buffer.alloc(1, 0),
  });

  console.log("✓ Transaction created");
  return psbt;
}

async function blindOutputs(
  psbt: Psbt,
  blindingPubkey: Buffer
  // blindingKeyPairs: ECPairInterface[]
): Promise<{ psbt: Psbt; ephemeralBlinds: any[] }> {
  // TODO: Use static blinding key, but generate a blinding keypair dynamically
  // Random asset blinds are used

  let ephemeralBlinds: ECPairInterface[] = [];
  let captureBlinds: liquidjs.KeysGenerator = (o) => {
    let getRandomKeypair = Psbt.ECCKeysGenerator(ecc);
    let randomKeypair = getRandomKeypair(o);
    ephemeralBlinds.push(ECPair.fromPrivateKey(randomKeypair.privateKey));
    return randomKeypair;
  };

  // Get my epehermeral privk somehow
  await psbt.blindOutputsByIndex(
    () => {
      return {
        privateKey: getBlindingKey().privateKey,
        publicKey: getBlindingKey().publicKey,
      };
    },
    new Map(),
    new Map().set(0, blindingPubkey)
  );

  console.log("✓ Outputs blinded");
  return { psbt, ephemeralBlinds };
}

function getBlindingDataFromAddress(confidentialAddr: string): {
  blindingPubKey: Buffer;
  unconfidentialAddress: string;
} {
  // Decode the confidential address to extract blinding public key
  const decoded = address.fromBlech32(confidentialAddr);

  return {
    blindingPubKey: decoded.pubkey,
    unconfidentialAddress: address.toBech32(
      decoded.data!.subarray(2),
      decoded.version,
      NETWORK.bech32
    ),
  };
}

function getNonce(nonceCommitmentHex: string, blindingKey: bigint): bigint {
  const ecdhNoncePreimage = sha256(
    secp256k1.Point.fromHex(nonceCommitmentHex)
      .multiply(Fn.create(blindingKey))
      .toBytes()
  );

  return BigInt("0x" + Buffer.from(sha256(ecdhNoncePreimage)).toString("hex"));
}

async function showMessages(outputIndex: number) {
  if (outputIndex === undefined) {
    outputIndex = 0;
  }

  console.log("cleared");
  let txs = {};
  let addressTxsResponse = await fetch(
    `${HOST}/address/${getPayment().address}/txs`
  );

  let addressTxs = await addressTxsResponse.json();
  let payment = getPayment();

  for (let tx of addressTxs.reverse() as any) {
    //99998600

      // if (tx.vin[0].prevout.scriptpubkey_address == getAddress()) {
      //   await showTxMessage(txs, tx.txid, outputIndex);
      // }

      if (tx.vout[0].scriptpubkey === payment.output.toString("hex")) {
        await showTxMessage(txs, tx.txid, outputIndex);
      }
  }

  console.log(txs);
  return txs;
}

function getValueFromConfidentialOutput(t: liquidjs.Transaction) {
  let nonceCommitmentHex = t.outs[OUTPUT_INDEX]?.nonce?.toString("hex");

  if (!nonceCommitmentHex) {
    return;
  }

  if (nonceCommitmentHex.length < 32) {
    return;
  }

  let verificationNonce = getNonce(
    nonceCommitmentHex,
    BigInt("0x" + getBlindingKey().privateKey.toString("hex"))
  );

  let decrypted = getDecryptedRingSignatureRangeProofFromOutput(
    verificationNonce,
    t.outs[OUTPUT_INDEX]
  );

  let valueBigIntArg: bigint = BigInt(
    "0x" + Buffer.from(decrypted.slice(decrypted.length - 8)).toString("hex")
  );

  return Number(valueBigIntArg);
}

async function getTx(txid: string) {
  let txHexResponse = await fetch(`${HOST}/tx/${txid}/hex`);
  let txHex = await txHexResponse.text();
  return liquidjs.Transaction.fromHex(txHex);
}

// Should have arg asking whether to include self-send
async function showTxMessage(txs, txid: string, outputIndex: number) {
  let txHexResponse = await fetch(`${HOST}/tx/${txid}/hex`);
  let txHex = await txHexResponse.text();
  let txFinal = liquidjs.Transaction.fromHex(txHex);

  if (txFinal?.outs[outputIndex]?.nonce?.length < 32) {
    return;
  }

  let nonceCommitmentHex = txFinal.outs[outputIndex]?.nonce?.toString("hex");

  if (!nonceCommitmentHex) {
    return;
  }

  if (nonceCommitmentHex.length < 32) {
    return;
  }

  let verificationNonce;

  let receiverConfidentialAddress = localStorage.getItem(txFinal.getId());
  let receiverUnconfidentialAddress;
  let blindingPublicKeyHex;

  // if i sent a message
  if (receiverConfidentialAddress) {
    console.log("I sent this:");
    let blindingData = getBlindingDataFromAddress(receiverConfidentialAddress);
    receiverUnconfidentialAddress = blindingData.unconfidentialAddress;

    blindingPublicKeyHex = blindingData.blindingPubKey.toString("hex");

    verificationNonce = getNonce(
      blindingData.blindingPubKey.toString("hex"),
      BigInt("0x" + getBlindingKey().privateKey.toString("hex"))
    );
  } else {
    blindingPublicKeyHex = nonceCommitmentHex;
    verificationNonce = getNonce(
      nonceCommitmentHex,
      BigInt("0x" + getBlindingKey().privateKey.toString("hex"))
    );
  }

  let decrypted = getDecryptedRingSignatureRangeProof(
    verificationNonce,
    txFinal,
    outputIndex
  );

  // Add entry to compiled convos
  let message = getMessageFromDecryptedSignature(26, 4, decrypted); //decrypted.subarray(64, 64 + 32);

  let txMetadataResponse = await fetch(`${HOST}/tx/${txid}`);
  let txMetadata = await txMetadataResponse.json();

  let messageComponents = message.toString("ascii").split(":");

  if (messageComponents.length < 3) {
    console.log("Incorrect number of message components");
    return;
  }

  if (messageComponents[0] != MESSAGE_PREFIX) {
    return;
  }

  let confidentialAddress = liquidjs.address.toConfidential(
    txMetadata.vin[0].prevout.scriptpubkey_address,
    txFinal?.outs[outputIndex]?.nonce
  );

  let isMine = !!receiverConfidentialAddress;
  let addressKey = isMine ? receiverConfidentialAddress : confidentialAddress;

  if (!txs[addressKey]) {
    txs[addressKey] = [];
  }


  let clientKey: string = messageComponents[1];
  let clientEncryptedMessage: string = messageComponents[2];
  let unencryptedMessage = decryptMessage(clientEncryptedMessage, Buffer.from(clientKey, "hex"))

  txs[addressKey].push({
    message: unencryptedMessage,
    confirmation_time: txMetadata.status.block_time,
    is_mine: isMine,
    explorer_url: `${EXPLORER_URL}/tx/${txid}`,
  });

  console.log("is_mine:", !!receiverConfidentialAddress);

  // Show message
  console.log("\n\nMESSAGE:\n\n", message.toString("ascii"));
}

function decryptMessage(encryptedMessage: string, salt: Uint8Array) {
  let messageBytes = Buffer.from(encryptedMessage, "hex");
  let key = sha256(salt);
  let j = 0;
  for (let i = 0; i < encryptedMessage.length; i++) {
    if (j === key.length) {
      key = sha256(key);
      j = 0;
    }

    if(messageBytes[i] === 0) {
      break;
    }
    messageBytes[i] ^= key[j];

    j++;
  }

  let clientDecryptedMessage = Buffer.from(messageBytes).toString("ascii");
  return clientDecryptedMessage;
}

function encryptMessage(message: string) {
  let messageBytes = message.split("").map((c) => c.charCodeAt(0));
  let salt = new Uint8Array(32);
  window.crypto.getRandomValues(salt);

  let key = sha256(salt);
  let j = 0;
  for (let i = 0; i < message.length; i++) {
    if (j === key.length) {
      key = sha256(key);
      j = 0;
    }

    messageBytes[i] ^= key[j];

    j++;
  }

  let clientEncryptedMessage = Buffer.from(messageBytes).toString("hex");
  return { salt: Buffer.from(salt).toString("hex"), clientEncryptedMessage };
}

async function sendBitcoin(confidentialAddress: string, message: string) {
  // const confidentialAddress =
  //   "el1qqfj44uf6v0wffqm5lnapr9rq4j49uzd7fq50djvn25v3ndlj5u8gcgrhu8g45sr6u5eh2gqyvumzy7nxxspk29mdf38fl94st";
  let recipientBlindingData = getBlindingDataFromAddress(confidentialAddress);

  let psbt = await createBlindedTransaction(
    recipientBlindingData.unconfidentialAddress,
    1000
  );

  let { ephemeralBlinds } = await blindOutputs(
    psbt,
    recipientBlindingData.blindingPubKey
  );
  let t = psbt
    .clone()
    .signAllInputs(getKeypair())
    .finalizeAllInputs()
    .extractTransaction();

  localStorage.setItem(t.getId(), confidentialAddress);

  // let nonceCommitment = t.outs[OUTPUT_INDEX].nonce.toString("hex");
  let verificationNonce = getNonce(
    recipientBlindingData.blindingPubKey.toString("hex"),
    BigInt("0x" + getBlindingKey().privateKey.toString("hex")) //BigInt("0x" + recipientBlindingData.blindingPubKey.toString("hex"))
  );

  debugger;

  let { salt, clientEncryptedMessage } = encryptMessage(message);
  t = modifyRangeProof(
    verificationNonce,
    t,
    OUTPUT_INDEX,
    `lm:${salt}:${clientEncryptedMessage}`
  );
  await submitTransaction(t.toHex());
  await showMessages(OUTPUT_INDEX);
}

async function submitTransaction(txHex: string): Promise<any> {
  const explorerUrl = `${HOST}/tx`;
  await fetch(explorerUrl, {
    method: "POST",
    body: txHex,
  });
}
//5001 is lqd exp
//3001 is lqd api
// sendBitcoin();

let recipientBlindingPrivateKey =
  0xfff68d254e89c7aeed25b02778e31778641802d426e256dbd703f2dfd932a45an;
// showMessages(0);

window.getAddress = getAddress;
window.getConfidentialAddress = getConfidentialAddress;
window.getBalance = async function () {
  await getUTXOs(getAddress());
  let totalValue = 0;

  if (!allUtxos) {
    return 0;
  }

  for (let utxo of allUtxos) {
    if (utxo.valuecommitment) {
      try {
        let tx = await getTx(utxo.txid);
        let value = getValueFromConfidentialOutput(tx);
        const MIN_VALUE = 1;
        totalValue += value + MIN_VALUE;
      } catch (e) {
        console.error(e);
      }
      continue;
    }

    totalValue += utxo.value;
  }

  console.log("Balance:", totalValue);
  return totalValue;
};
window.sendBitcoin = sendBitcoin;
window.showMessages = showMessages;

export { ecc, liquidjs, ECPairFactory };
