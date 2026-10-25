import ObjC from "frida-objc-bridge";

const {
    NSBundle, NSData, NSString, NSPropertyListSerialization,
    IDSValidationQueue, IDSValidationSession, IDSBaseMessageSigningData,
    AKAnisetteProvisioningController, AKAttestationRequestData, AKDevice,
} = ObjC.classes;

const absintheSignings: any[] = [];

const VALIDATION_SUBSYSTEM = "com.apple.private.alloy.facetime.multi";
const NS_PROPERTY_LIST_XML = 100;

interface ValidationRequest {
    bag_key: string;
    method: string;
    headers: Record<string, string>;
    body?: string;
}

interface ValidationState {
    queue: ObjC.Object;
    subsystem: ObjC.Object;
    nacSign: NacSignFunction;
    retained: any[];
    currentMessage: ObjC.Object | null;
    onRequest: ((request: ValidationRequest) => void) | null;
    onComplete: (() => void) | null;
}

let activeValidation: ValidationState | null = null;

rpc.exports = {
    deviceInfo(): Record<string, string> {
        return {
            hardware_version: sysctl("hw.model"),
            software_name: "macOS",
            software_version: sysctl("kern.osproductversion"),
            software_build_id: sysctl("kern.osversion"),
            serial_number: ioPlatformProperty("IOPlatformSerialNumber"),
            unique_device_id: ioPlatformProperty("IOPlatformUUID"),
            push_user_agent: pushUserAgent(),
        };
    },

    fairplaySign(activationInfoB64: string): Record<string, string> {
        const sign = locateFairPlaySigner();

        const digestInfo = Memory.alloc(35);
        digestInfo.writeByteArray([
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        ]);
        const input = decodeBase64(activationInfoB64);
        ccSha1(input.bytes, input.length, digestInfo.add(15));

        const sig = Memory.alloc(256);
        const sigLen = Memory.alloc(4).writeU32(256);
        const chain = Memory.alloc(4096);
        const chainLen = Memory.alloc(4).writeU32(4096);

        const r = sign(digestInfo, 35, sig, sigLen, chain, chainLen) as number;
        const producedSig = sigLen.readU32();
        const producedChain = chainLen.readU32();
        if (r !== 0 || producedSig !== 128 || producedChain === 0 || producedChain > 4096)
            throw new Error(`FairPlay signer gave an implausible result (r=${r}, sig=${producedSig}, chain=${producedChain})`);

        return {
            signature: encodeBase64(sig, producedSig),
            certificate_chain: encodeBase64(chain, producedChain),
        };
    },

    validationBegin(): Promise<Record<string, any>> {
        const retained: any[] = [];
        const subsystem = NSString.stringWithUTF8String_(Memory.allocUtf8String(VALIDATION_SUBSYSTEM));
        retained.push(subsystem);

        const state: ValidationState = {
            queue: null as unknown as ObjC.Object,
            subsystem,
            nacSign: locateNACSign(),
            retained,
            currentMessage: null,
            onRequest: null,
            onComplete: null,
        };

        const sendBlock = new ObjC.Block({
            retType: "void",
            argTypes: ["object"],
            implementation: (message: ObjC.Object) => {
                message.retain();
                state.currentMessage = message;
                const handler = state.onRequest;
                state.onRequest = null;
                if (handler !== null)
                    handler(extractRequest(message));
            },
        });
        retained.push(sendBlock);

        const queueCompletion = new ObjC.Block({
            retType: "void",
            argTypes: ["bool"],
            implementation: () => {
                const handler = state.onComplete;
                state.onComplete = null;
                if (handler !== null)
                    handler();
            },
        });
        retained.push(queueCompletion);

        const queue = IDSValidationQueue.alloc().initWithValidationMessageSendBlock_(sendBlock);
        queue.setShouldUseAbsinthe_(true);
        state.queue = queue;
        activeValidation = state;

        return awaitValidationStep(state, () => objcMsgSend(queue.handle,
            ObjC.selector("queueBuildingValidationDataIfNecessaryForMessage:subsystem:withQueueCompletion:sendBlock:"),
            NULL, subsystem.handle, queueCompletion.handle, sendBlock.handle));
    },

    validationContinue(status: number, responseBase64: string): Promise<Record<string, any>> {
        const state = activeValidation;
        if (state === null || state.currentMessage === null)
            throw new Error("no validation request is awaiting a response");

        const message = state.currentMessage;
        state.currentMessage = null;

        const data = NSData.alloc().initWithBase64EncodedString_options_(responseBase64, 0);
        const dict = (data !== null && !data.handle.isNull() && data.length().valueOf() > 0)
            ? NSPropertyListSerialization.propertyListWithData_options_format_error_(data, 0, NULL, NULL)
            : NULL;

        return awaitValidationStep(state, () => {
            message.handleResponseDictionary_(dict);
            invokeCompletionBlock(message.completionBlock(), message, NULL, status);
            message.release();
        });
    },

    anisette(): Record<string, string> {
        const controller = AKAnisetteProvisioningController.alloc().init();
        const error = Memory.alloc(Process.pointerSize).writePointer(NULL);
        const data = controller.anisetteDataWithError_(error);
        if (data.handle.isNull())
            throw new Error(new ObjC.Object(error.readPointer()).toString());

        const device = AKDevice.currentDevice();
        return {
            "X-Apple-I-MD": data.oneTimePassword().toString(),
            "X-Apple-I-MD-M": data.machineID().toString(),
            "X-Apple-I-MD-RINFO": data.routingInfo().toString(),
            "X-Apple-I-MD-LU": device.localUserUUID().toString(),
            "X-Apple-I-SRL-NO": device.serialNumber().toString(),
            "X-Mme-Device-Id": device.uniqueDeviceIdentifier().toString(),
            "X-MMe-Client-Info": device.serverFriendlyDescription().toString(),
        };
    },

    baaHeaders(): Record<string, string> {
        const controller = AKAnisetteProvisioningController.alloc().init();
        const request = AKAttestationRequestData.alloc().init();
        const error = Memory.alloc(Process.pointerSize).writePointer(NULL);
        const attestation = controller.attestationDataForRequestData_error_(request, error);
        if (attestation.handle.isNull())
            throw new Error(new ObjC.Object(error.readPointer()).toString());
        return dictionaryToObject(attestation.allHeaders());
    },

    absintheHeaders(digestBase64: string, bodyBase64: string): Promise<Record<string, string>> {
        return new Promise((resolve, reject) => {
            const queue = imPrimaryQueue();
            const digest = NSData.alloc().initWithBase64EncodedString_options_(digestBase64, 0);
            const body = NSData.alloc().initWithBase64EncodedString_options_(bodyBase64, 0);
            const retained: any[] = [digest, body];
            absintheSignings.push(retained);

            const onHeaders = new ObjC.Block({
                retType: "void",
                argTypes: ["object", "object"],
                implementation: (headers: ObjC.Object | null, error: ObjC.Object | null) => {
                    if (headers === null || headers.handle.isNull())
                        reject(new Error(error !== null ? error.description().toString() : "signing produced no headers"));
                    else
                        resolve(dictionaryToObject(headers));
                },
            });
            const onSession = new ObjC.Block({
                retType: "void",
                argTypes: ["object", "object"],
                implementation: (session: ObjC.Object | null, error: ObjC.Object | null) => {
                    if (session === null || session.handle.isNull()) {
                        reject(new Error(error !== null ? error.description().toString() : "could not establish a validation session"));
                        return;
                    }
                    const signingData = IDSBaseMessageSigningData.alloc()
                        .initWithSHA256Digest_requestBody_serverTimestamp_includeIcloudBAA_(digest, body, Date.now(), 1);
                    retained.push(signingData);
                    session.headersBySigningData_completion_(signingData, onHeaders);
                },
            });
            const launch = new ObjC.Block({
                retType: "void",
                argTypes: [],
                implementation: () => IDSValidationSession.absintheValidationSessionOnQueue_withCompletion_(queue, onSession),
            });
            retained.push(onHeaders, onSession, launch);

            dispatchAsync(queue, launch.handle);
        });
    },
};

function sysctl(name: string): string {
    const size = Memory.alloc(Process.pointerSize);
    const key = Memory.allocUtf8String(name);
    if (sysctlbyname(key, NULL, size, NULL, NULL) !== 0)
        return "";
    const len = size.readULong();
    if (len === 0)
        return "";
    const buffer = Memory.alloc(len);
    if (sysctlbyname(key, buffer, size, NULL, NULL) !== 0)
        return "";
    return buffer.readUtf8String() ?? "";
}

function ioPlatformProperty(key: string): string {
    const service = IOServiceGetMatchingService(0, IOServiceMatching(Memory.allocUtf8String("IOPlatformExpertDevice")));
    if (service === 0)
        return "";
    const name = NSString.stringWithUTF8String_(Memory.allocUtf8String(key));
    const value = IORegistryEntryCreateCFProperty(service, name.handle, NULL, 0) as NativePointer;
    IOObjectRelease(service);
    if (value.isNull())
        return "";
    return new ObjC.Object(value).toString();
}

// The exact User-Agent apsd presents: "apsd (unknown version) CFNetwork/<ver> Darwin/<kernel>".
// CFNetwork's version comes from its bundle so a Linux client can send the same string.
function pushUserAgent(): string {
    let cfnetwork = "";
    const bundle = NSBundle.bundleWithIdentifier_("com.apple.CFNetwork");
    if (!bundle.handle.isNull()) {
        const version = bundle.infoDictionary().objectForKey_("CFBundleVersion");
        if (version !== null)
            cfnetwork = version.toString();
    }
    return `apsd (unknown version) CFNetwork/${cfnetwork} Darwin/${sysctl("kern.osrelease")}`;
}

function locateFairPlaySigner(): SignerFunction {
    const anchor = ObjC.classes.APSCertificateProvisioner["- generateClientIdentity"].implementation.strip("ia");
    const apsd = Process.getModuleByName("apsd");

    let afterDigestLength = false;
    let cursor = anchor;
    for (let i = 0; i < 4096; i++) {
        const insn = Instruction.parse(cursor) as Arm64Instruction;
        const mnemonic = insn.mnemonic;
        const operands = insn.operands;
        cursor = insn.next;

        if (mnemonic === "bl" && afterDigestLength) {
            const target = ptr((operands[0] as Arm64ImmOperand).value.toString());
            if (isInsideModule(target, apsd))
                return new NativeFunction(target.sign("ia"), "int",
                    ["pointer", "uint32", "pointer", "pointer", "pointer", "pointer"]) as SignerFunction;
        }
        afterDigestLength = isImmediateMove(mnemonic, operands, "w1", 0x23);
    }
    throw new Error("FairPlay signer not found: apsd layout changed, re-derive before trusting output");
}

type SignerFunction = (digestInfo: NativePointer, digestLen: number, sig: NativePointer,
    sigLen: NativePointer, chain: NativePointer, chainLen: NativePointer) => number;

function locateNACSign(): NacSignFunction {
    const anchor = IDSValidationQueue["- queueBuildingValidationDataIfNecessaryForMessage:subsystem:withQueueCompletion:sendBlock:"]
        .implementation.strip("ia");
    const ids = Process.getModuleByName("identityservicesd");

    const recent: Arm64Operand[][] = [];
    let cursor = anchor;
    for (let i = 0; i < 2048; i++) {
        const insn = Instruction.parse(cursor) as Arm64Instruction;
        const mnemonic = insn.mnemonic;
        const operands = insn.operands;
        cursor = insn.next;

        if (mnemonic === "bl") {
            const target = ptr((operands[0] as Arm64ImmOperand).value.toString());
            if (isInsideModule(target, ids)
                    && recent.some(ops => isZeroed(ops, "x1")) && recent.some(ops => isZeroed(ops, "w2"))) {
                return new NativeFunction(target.sign("ia"), "int",
                    ["pointer", "pointer", "int", "pointer", "pointer"]) as NacSignFunction;
            }
        }

        if (mnemonic === "mov" || mnemonic === "movz") {
            recent.push(operands);
            if (recent.length > 8)
                recent.shift();
        }
    }
    throw new Error("NACSign not found: identityservicesd layout changed, re-derive before trusting output");
}

type NacSignFunction = (ctx: NativePointer, data: NativePointer, dataLen: number,
    out: NativePointer, outLen: NativePointer) => number;

function isInsideModule(address: NativePointer, module: Module): boolean {
    return address.compare(module.base) >= 0 && address.compare(module.base.add(module.size)) < 0;
}

function isImmediateMove(mnemonic: string, operands: Arm64Operand[], register: string, value: number): boolean {
    if (mnemonic !== "mov" && mnemonic !== "movz")
        return false;
    if (operands.length !== 2)
        return false;
    const [destination, source] = operands;
    return destination.type === "reg" && destination.value === register
        && source.type === "imm" && source.value.toNumber() === value;
}

function isZeroed(operands: Arm64Operand[], register: string): boolean {
    if (operands.length < 2)
        return false;
    const [destination, source] = operands;
    if (destination.type !== "reg" || destination.value !== register)
        return false;
    if (source.type === "imm")
        return source.value.toNumber() === 0;
    return source.type === "reg" && (source.value === "xzr" || source.value === "wzr");
}

function awaitValidationStep(state: ValidationState, trigger: () => void): Promise<Record<string, any>> {
    return new Promise((resolve, reject) => {
        let settled = false;
        const deadline = Date.now() + 30000;

        const cleanup = () => {
            state.onRequest = null;
            state.onComplete = null;
        };
        const succeed = (value: Record<string, any>) => {
            if (settled)
                return;
            settled = true;
            cleanup();
            resolve(value);
        };
        const fail = (reason: Error) => {
            if (settled)
                return;
            settled = true;
            cleanup();
            reject(reason);
        };
        const signIfReady = () => {
            activeValidation = null;
            const result = trySign(state);
            if (result !== null)
                succeed({ done: true, ...result });
            else
                fail(new Error("validation completed without a signable context"));
        };

        state.onRequest = (request: ValidationRequest) => succeed({ done: false, request });
        state.onComplete = signIfReady;

        const poll = () => {
            if (settled)
                return;
            const result = trySign(state);
            if (result !== null) {
                activeValidation = null;
                succeed({ done: true, ...result });
            } else if (Date.now() < deadline) {
                dispatchAfterOnPrimaryQueue(state, poll);
            } else {
                fail(new Error("timed out producing validation data"));
            }
        };

        dispatchOnPrimaryQueue(state, () => {
            trigger();
            if (!settled)
                poll();
        });
    });
}

function dispatchOnPrimaryQueue(state: ValidationState, fn: () => void): void {
    const block = new ObjC.Block({ retType: "void", argTypes: [], implementation: fn });
    state.retained.push(block);
    dispatchAsync(imPrimaryQueue(), block.handle);
}

function dispatchAfterOnPrimaryQueue(state: ValidationState, fn: () => void): void {
    const block = new ObjC.Block({ retType: "void", argTypes: [], implementation: fn });
    state.retained.push(block);
    dispatchAfter(dispatchTime(0, 50 * 1000 * 1000), imPrimaryQueue(), block.handle);
}

function dictionaryToObject(dictionary: ObjC.Object): Record<string, string> {
    const result: Record<string, string> = {};
    const keys = dictionary.allKeys();
    const count = keys.count().valueOf();
    for (let i = 0; i !== count; i++) {
        const key = keys.objectAtIndex_(i);
        result[key.toString()] = dictionary.objectForKey_(key).toString();
    }
    return result;
}

function extractRequest(message: ObjC.Object): ValidationRequest {
    const get = message.wantsHTTPGet();

    const headers: Record<string, string> = { "User-Agent": validationUserAgent() };
    const extra = message.additionalMessageHeaders();
    if (extra !== null && !extra.handle.isNull()) {
        const keys = extra.allKeys();
        const count = keys.count().valueOf();
        for (let i = 0; i !== count; i++) {
            const key = keys.objectAtIndex_(i);
            headers[key.toString()] = extra.objectForKey_(key).toString();
        }
    }

    const request: ValidationRequest = {
        bag_key: message.bagKey().toString(),
        method: get ? "GET" : "POST",
        headers,
    };

    if (!get) {
        headers["Content-Type"] = "application/x-apple-plist";
        const body = messageBodyData(message);
        if (body !== null)
            request.body = encodeBase64(body.bytes(), body.length().valueOf());
    }

    return request;
}

function validationUserAgent(): string {
    return `com.apple.invitation-registration [macOS,${sysctl("kern.osproductversion")},${sysctl("kern.osversion")},${sysctl("hw.model")}]`;
}

function messageBodyData(message: ObjC.Object): ObjC.Object | null {
    const body = message.messageBody();
    if (body === null || body.handle.isNull())
        return null;
    if (body.isKindOfClass_(NSData))
        return body;
    return NSPropertyListSerialization.dataWithPropertyList_format_options_error_(body, NS_PROPERTY_LIST_XML, 0, NULL);
}

function invokeCompletionBlock(block: ObjC.Object, message: ObjC.Object, error: ObjC.Object | NativePointer, status: number): void {
    if (block === null || block.handle.isNull())
        return;
    const callable = new ObjC.Block(block.handle);
    if (callable.types === undefined)
        callable.declare({ retType: "void", argTypes: ["object", "object", "int64", "object"] });
    callable.implementation(message, error, int64(status), NULL);
}

function trySign(state: ValidationState): Record<string, string> | null {
    const infoHandle = objcMsgSendInfo(state.queue.handle,
        ObjC.selector("_validationInfoForSubsystem:createIfNil:"), state.subsystem.handle, 0) as NativePointer;
    if (infoHandle.isNull())
        return null;
    const info = new ObjC.Object(infoHandle);
    const context = info.handle.add(32).readPointer();
    if (info.handle.add(9).readU8() !== 0 || context.isNull())
        return null;

    const ttl = info.validateContextTTL();
    if (ttl === null || ttl.handle.isNull())
        return null;

    const out = Memory.alloc(Process.pointerSize);
    const outLen = Memory.alloc(4);
    const r = state.nacSign(context, NULL, 0, out, outLen);
    const blob = out.readPointer();
    const length = outLen.readU32();
    if (r !== 0 || blob.isNull() || length < 200 || length > 4096)
        return null;

    return {
        validation_data: encodeBase64(blob, length),
        valid_until: validUntil(info.validateContextDate(), ttl),
    };
}

function validUntil(date: ObjC.Object, ttl: ObjC.Object): string {
    const base = (date !== null && !date.handle.isNull())
        ? date.timeIntervalSince1970().valueOf() * 1000
        : Date.now();
    return new Date(base + ttl.doubleValue().valueOf() * 1000).toISOString();
}

function decodeBase64(text: string): { bytes: NativePointer; length: number } {
    const data = NSData.alloc().initWithBase64EncodedString_options_(text, 0);
    return { bytes: data.bytes(), length: data.length().valueOf() };
}

function encodeBase64(bytes: NativePointer, length: number): string {
    return NSData.dataWithBytes_length_(bytes, length).base64EncodedStringWithOptions_(0).toString();
}

const objcMsgSend = new NativeFunction(Module.getGlobalExportByName("objc_msgSend"), "void",
    ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer"]);
const objcMsgSendInfo = new NativeFunction(Module.getGlobalExportByName("objc_msgSend"), "pointer",
    ["pointer", "pointer", "pointer", "bool"]);
const imPrimaryQueue = new NativeFunction(Module.getGlobalExportByName("im_primary_queue"), "pointer", []);
const dispatchAsync = new NativeFunction(Module.getGlobalExportByName("dispatch_async"), "void",
    ["pointer", "pointer"]);
const dispatchAfter = new NativeFunction(Module.getGlobalExportByName("dispatch_after"), "void",
    ["uint64", "pointer", "pointer"]);
const dispatchTime = new NativeFunction(Module.getGlobalExportByName("dispatch_time"), "uint64",
    ["uint64", "int64"]);
const sysctlbyname = new NativeFunction(Module.getGlobalExportByName("sysctlbyname"), "int",
    ["pointer", "pointer", "pointer", "pointer", "pointer"]);
const ccSha1 = new NativeFunction(Module.getGlobalExportByName("CC_SHA1"), "pointer",
    ["pointer", "uint32", "pointer"]);
const IOServiceMatching = new NativeFunction(Module.getGlobalExportByName("IOServiceMatching"), "pointer",
    ["pointer"]);
const IOServiceGetMatchingService = new NativeFunction(Module.getGlobalExportByName("IOServiceGetMatchingService"), "uint",
    ["uint", "pointer"]);
const IORegistryEntryCreateCFProperty = new NativeFunction(Module.getGlobalExportByName("IORegistryEntryCreateCFProperty"), "pointer",
    ["uint", "pointer", "pointer", "uint32"]);
const IOObjectRelease = new NativeFunction(Module.getGlobalExportByName("IOObjectRelease"), "int",
    ["uint"]);
