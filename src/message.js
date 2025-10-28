import { getSecIdx } from "./utils";
function stringToHex(str) {
    let hexBytes = [];
    for (let i = 0; i < str.length; i++) {
        // Get the character code (ASCII/Unicode value)
        let charCode = str.charCodeAt(i);
        // Convert to hexadecimal and pad with a leading '0' if necessary
        let hex = charCode.toString(16).padStart(2, "0");
        hexBytes.push(hex);
    }
    return hexBytes.join(""); // Join the hex values to form a single hex string
}
const SIGNATURE_SIZE = 32;
function getMessage(numRings, ringSize, assetId, assetBlinder, valueHex, lastSignerIndexIsAtEndOfRing = false, message = "") {
    let lastRingIndex = numRings - 1;
    let lastIndexOfRing = ringSize - 1;
    if (lastSignerIndexIsAtEndOfRing) {
        lastIndexOfRing -= 1;
    }
    let lastRingPosition = lastRingIndex * ringSize;
    let lastRingPositionInSignatureBuffer = (lastRingPosition + lastIndexOfRing) * SIGNATURE_SIZE;
    let sizeOfAssetInfo = assetId.length / 2 + assetBlinder.length / 2;
    let bufferIndexOfWhereToWriteValue = lastRingPositionInSignatureBuffer + 8;
    let embeddedMessage = stringToHex(message);
    // will equal 3240 unless signer index for last ring is defined as last
    // this is impossible when sending smaller amounts.
    let numberOfZeros = bufferIndexOfWhereToWriteValue -
        sizeOfAssetInfo -
        embeddedMessage.length / 2;
    let zeros = new Array(numberOfZeros).fill(0).reduce((acc, n) => {
        return Buffer.from([...acc, n]);
    }, Buffer.from([]));
    let secidx = getSecIdx(BigInt("0x" + valueHex));
    let fakeSignatures = "";
    let hexMessageToBeWritten = embeddedMessage.slice();
    for (let ringIndex = 0; ringIndex < numRings; ringIndex++) {
        for (let sigIndex = 0; sigIndex < ringSize; sigIndex++) {
            if (ringIndex === 0 && sigIndex === 0) {
                fakeSignatures += assetId;
                continue;
            }
            if (ringIndex === 0 && sigIndex === 1) {
                fakeSignatures += assetBlinder;
                continue;
            }
            if (secidx[ringIndex] === sigIndex) {
                fakeSignatures += Buffer.from(new Array(SIGNATURE_SIZE).fill(0)).toString("hex");
                continue;
            }
            if (ringIndex === numRings - 1) {
                if (secidx[ringIndex] === ringSize - 1) {
                    if (sigIndex === ringSize - 2) {
                        fakeSignatures +=
                            "0000000000000000" + valueHex + valueHex + valueHex;
                        continue;
                    }
                }
                else if (sigIndex === ringSize - 1) {
                    fakeSignatures += "0000000000000000" + valueHex + valueHex + valueHex;
                    continue;
                }
            }
            let fakeSig = hexMessageToBeWritten.substring(0, 64);
            fakeSig = fakeSig.padEnd(64, "00");
            fakeSignatures += fakeSig;
            hexMessageToBeWritten = hexMessageToBeWritten.substring(64);
        }
    }
    // 3 of these is 32 bytes since value is represented with 8 bytes
    // let valueHex = "0000000005f5e0ff";
    let hex = fakeSignatures;
    let messageBytes = Uint8Array.from(Buffer.from(hex, "hex")); // 3317? should be 3328
    //3296 (((rings - 1) * 4 + 3) * 32) should have the value 128
    messageBytes[lastRingPositionInSignatureBuffer] = 128;
    return messageBytes;
}
export function getMessageFromDecryptedSignature(numRings, ringSize, decryptedSignatureData) {
    let startIndex = decryptedSignatureData.length - 8;
    let endIndex = startIndex + 8;
    let lastValueBytes = decryptedSignatureData.subarray(startIndex, endIndex);
    let secondToLastValueBytes = decryptedSignatureData.subarray(startIndex - 8, endIndex - 8);
    if (!lastValueBytes.equals(secondToLastValueBytes)) {
        startIndex -= SIGNATURE_SIZE;
        endIndex -= SIGNATURE_SIZE;
    }
    let valueHex = decryptedSignatureData
        .subarray(startIndex, endIndex)
        .toString("hex");
    let secidx = getSecIdx(BigInt("0x" + valueHex));
    let decryptedMessage;
    for (let ringIndex = 0; ringIndex < numRings; ringIndex++) {
        for (let sigIndex = 0; sigIndex < ringSize; sigIndex++) {
            if (ringIndex === 0 && sigIndex === 0) {
                //assetId;
                continue;
            }
            if (ringIndex === 0 && sigIndex === 1) {
                //assetBlinder;
                continue;
            }
            if (secidx[ringIndex] === sigIndex) {
                // real signature
                continue;
            }
            if (ringIndex === numRings - 1) {
                if (secidx[ringIndex] === ringSize - 1) {
                    if (sigIndex === ringSize - 2) {
                        // skip value encoding
                        continue;
                    }
                }
                else if (sigIndex === ringSize - 1) {
                    // skip value encoding
                    continue;
                }
            }
            let startOfMessageChunk = ringIndex * ringSize * SIGNATURE_SIZE + sigIndex * SIGNATURE_SIZE;
            let endOfMessageChunk = startOfMessageChunk + SIGNATURE_SIZE;
            let message = decryptedSignatureData.subarray(startOfMessageChunk, endOfMessageChunk);
            console.log(`CHUNK ${ringIndex}, ${sigIndex}:`, Buffer.from(message).toString("ascii"));
            if (!decryptedMessage) {
                decryptedMessage = message;
            }
            else {
                decryptedMessage = Buffer.concat([decryptedMessage, message]);
            }
        }
    }
    return decryptedMessage;
}
//3328 in size
export default getMessage;
