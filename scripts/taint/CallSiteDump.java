import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

/**
 * call-site-dump — per-caller-function call-site inventory for spec
 * composition (taint stage, Phase-1 Mapper input).
 *
 * One binary in, one JSON out. For every function that contains call
 * instructions, emits every call site with ALL CALLER-SIDE FACTS the
 * dynamic verifier needs to author a probe:
 *
 *   call        address of the call instruction
 *   ret_site    its fall-through (return site; Ghidra computes delay slots)
 *   callee      best-effort resolved name/address (thunks/PLT included);
 *               null for indirect calls — every other fact still stands
 *   args        per position: the PHYSICAL location (calling-convention
 *               register/stack slot — the ABI register the value will sit
 *               in at the call) plus, when resolvable, the constant value
 *               (const_string / const_int / const_addr)
 *   ret         the ABI return register for the callee's convention, plus
 *               a bounded forward consumer scan (where the return value
 *               flows: store/move/deref/passed-to-call)
 *
 * Three evidence paths, unioned per fact, all caller-side:
 *   pcode       the decompiler's call op at the instruction address — arg
 *               VALUES (folded constants) and the dataflow varnodes
 *   text        the decompiled C call expressions — string literals and
 *               PIC address arithmetic (DAT_x ± const, PTR_lbl_slot ±
 *               const) resolved through the program's memory
 *   raw pcode   STORE/LOAD/COPY shapes of instructions after the return
 *               site — the consumer scan
 *
 * The pcode input varnodes are HighVariable REPRESENTATIVES (dataflow
 * sources), NOT physical ABI slots — two different args can show the same
 * register. That is why `loc` comes from the calling-convention model
 * (PrototypeModel.getArgLocation) and the varnode is kept separately as
 * `vn` evidence. Position joins between pcode/text/ABI are marked in
 * `binding` and degrade honestly to null.
 *
 * Determinism: functions, call sites, args and consumers all emit in
 * address order; no clocks, no hashing, no map iteration in the output.
 */
public class CallSiteDump extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT = 60;   // seconds per function
    private static final int STR_MAX = 128;            // raw-ASCII string probe length
    private static final int CONSUMER_WINDOW = 12;     // instructions scanned after ret_site
    private static final int MAX_ARGS = 12;            // positions bound per call site
    private static final int TEXT_MAX = 160;           // per-arg raw C text kept

    private static final Pattern DAT_ARITH = Pattern.compile(
        "DAT_([0-9a-f]+)\\s*(?:([+\\-])\\s*0x([0-9a-f]+))?");
    private static final Pattern DAT_ARITH_REV = Pattern.compile(
        "0x([0-9a-f]+)\\s*\\+\\s*DAT_([0-9a-f]+)");
    private static final Pattern PTR_ARITH = Pattern.compile(
        "\\bPTR_([A-Za-z0-9_.+-]*[A-Za-z0-9_.+])_([0-9a-f]{4,})(?![A-Za-z0-9_.+-])"
        + "(?:\\s*([+\\-])\\s*(?:([+\\-])\\s*)?0x([0-9a-f]+))?");
    // indirect call in decompiled C: (*(code *)PTR_callee_00084a04)(args)
    private static final Pattern CALL_IND_RE = Pattern.compile(
        "\\(\\*\\(code\\s*\\*\\)\\s*PTR_([A-Za-z0-9_.+-]*?)_([0-9a-f]{4,})\\)"
        + "\\s*\\(([^;]{0,400}?)\\)");
    private static final Pattern STR_LIT = Pattern.compile(
        "\"((?:[^\"\\\\]|\\\\.){1,96})\"");
    // a cast's content is type-shaped (identifier words, optional *): this
    // must NOT swallow a parenthesized argument expression like
    // (DAT_x + 0xc); the code also requires a non-empty remainder
    private static final Pattern CAST_PREFIX = Pattern.compile(
        "^\\(\\s*[A-Za-z_][A-Za-z0-9_]*(?:\\s+[A-Za-z_][A-Za-z0-9_]*)*\\s*\\*?\\s*\\)");

    private static final Set<String> CALL_KEYWORDS = Set.of(
        "if", "for", "while", "switch", "return", "sizeof", "else", "do",
        "case", "default", "goto", "break", "continue", "typeof", "defined");

    // ---- state -----------------------------------------------------------
    private Memory memory;
    private AddressSpace space;
    private int ptrSize;
    private DataType wordType;
    private PrototypeModel defaultCC;

    // (convention name -> (arg position -> storage)) cache; conventions are
    // shared by thousands of call sites
    private final Map<String, Map<Integer, VariableStorage>> locCache = new HashMap<>();

    // stats
    private long fnTotal, fnWithCalls, sites, indirectSites, constArgs,
        textJoined, decompFail, consumerCount;

    // ------------------------------------------------------------------
    @Override
    protected void run() {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("CallSiteDump: usage: CallSiteDump.java <out.json> [binary-display-path]");
            return;
        }
        String outPath = args[0];
        String binaryDisplay = args.length > 1 ? args[1] : "";
        String binaryFile = args.length > 2 ? args[2] : "";
        memory = currentProgram.getMemory();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        ptrSize = space.getSize() / 8;
        wordType = ptrSize >= 8 ? new QWordDataType() : new DWordDataType();
        defaultCC = currentProgram.getCompilerSpec().getDefaultCallingConvention();

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        StringBuilder sb = new StringBuilder(1 << 20);
        sb.append("{\n");
        writeHeader(sb, binaryDisplay, binaryFile);
        sb.append("  \"functions\": [\n");
        boolean firstFn = true;
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = fit.next();
            fnTotal++;
            List<Instruction> calls = callInstructions(f);
            if (calls.isEmpty()) continue;
            fnWithCalls++;
            String fnJson = dumpFunction(dec, f, calls);
            if (fnJson == null) continue;
            if (!firstFn) sb.append(",\n");
            firstFn = false;
            sb.append(fnJson);
            if (fnWithCalls % 500 == 0) {
                println("CallSiteDump: progress fn=" + fnWithCalls
                    + " sites=" + sites);
            }
        }
        sb.append(fnWithCalls > 0 ? "\n" : "").append("  ],\n");
        writeStats(sb);
        sb.append("}\n");
        dec.dispose();
        try (PrintWriter pw = new PrintWriter(outPath, StandardCharsets.UTF_8)) {
            pw.print(sb);
        } catch (Exception e) {
            println("CallSiteDump: WRITE ERROR " + e);
            return;
        }
        println("CallSiteDump: functions=" + fnWithCalls + "/" + fnTotal
            + " sites=" + sites + " indirect=" + indirectSites
            + " const_args=" + constArgs + " text_joined=" + textJoined
            + " decomp_fail=" + decompFail + " consumers=" + consumerCount
            + " -> " + outPath);
    }

    // ---- program header ------------------------------------------------
    private void writeHeader(StringBuilder sb, String binaryDisplay, String binaryFile) {
        sb.append("  \"tool\": \"call-site-dump\",\n");
        sb.append("  \"binary\": ").append(q(binaryDisplay)).append(",\n");
        sb.append("  \"et_type\": ").append(q(etType(binaryFile))).append(",\n");
        sb.append("  \"image_base\": \"").append(hex(currentProgram.getImageBase().getOffset()))
            .append("\",\n");
        sb.append("  \"arch\": {\"processor\": ")
            .append(q(currentProgram.getLanguage().getProcessor().toString()))
            .append(", \"endian\": ").append(currentProgram.getLanguage().isBigEndian()
                ? "\"big\"" : "\"little\"")
            .append(", \"bits\": ").append(ptrSize * 8)
            .append(", \"ptr_size\": ").append(ptrSize).append("},\n");
    }

    /**
     * e_type straight from the ELF file header (offset 0 — the mapped image
     * usually starts past the header, so a memory read misses it). Falls
     * back to the program's lowest mapped address when no file is given.
     */
    private String etType(String binaryFile) {
        try (java.io.FileInputStream in = binaryFile != null && !binaryFile.isEmpty()
                ? new java.io.FileInputStream(binaryFile) : null) {
            byte[] h;
            if (in != null) {
                h = in.readNBytes(20);
            } else {
                h = new byte[20];
                memory.getBytes(currentProgram.getMinAddress(), h);
            }
            if (h.length < 20 || (h[0] & 0xff) != 0x7f || h[1] != 'E' || h[2] != 'L'
                    || h[3] != 'F') {
                return "unknown";
            }
            int et = h[5] == 2
                ? ((h[16] & 0xff) << 8) | (h[17] & 0xff)   // EI_DATA=2: big endian
                : (h[16] & 0xff) | ((h[17] & 0xff) << 8);  // EI_DATA=1: little endian
            switch (et) {
                case 1: return "REL";
                case 2: return "EXEC";
                case 3: return "DYN";
                default: return "unknown";
            }
        } catch (Exception e) {
            return "unknown";
        }
    }

    private void writeStats(StringBuilder sb) {
        sb.append("  \"stats\": {\"functions_total\": ").append(fnTotal)
            .append(", \"functions_with_calls\": ").append(fnWithCalls)
            .append(", \"call_sites\": ").append(sites)
            .append(", \"indirect_sites\": ").append(indirectSites)
            .append(", \"args_with_const\": ").append(constArgs)
            .append(", \"text_joined\": ").append(textJoined)
            .append(", \"decompile_failures\": ").append(decompFail)
            .append(", \"consumers\": ").append(consumerCount).append("}\n");
    }

    // ---- per-function dump ----------------------------------------------
    private static final class FnCtx {
        // ALL call expressions from the decompiled C, text order, consumed
        // on join. Direct form `name(args)` and the MIPS/GOT indirect form
        // `(*(code *)PTR_name_slot)(args)` are keyed by the SAME name — on
        // MIPS every external call renders as the PTR form, so resolved
        // callees must find their text evidence there.
        final List<TextCall> texts = new ArrayList<>();
    }

    private String dumpFunction(DecompInterface dec, Function f, List<Instruction> calls) {
        try {
            // decompile ONCE per caller; pcode + text both come from it
            DecompileResults dr = dec.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);
            boolean decompOk = dr != null && dr.decompileCompleted() && dr.getHighFunction() != null;
            if (!decompOk) decompFail++;

            FnCtx ctx = new FnCtx();
            Map<Long, PcodeOp> callOps = new HashMap<>();
            if (decompOk) {
                java.util.Iterator<PcodeOpAST> pit = dr.getHighFunction().getPcodeOps();
                while (pit.hasNext()) {
                    PcodeOp op = pit.next();
                    if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                        long a = op.getSeqnum().getTarget().getOffset();
                        if (!callOps.containsKey(a)) callOps.put(a, op);
                    }
                }
                String c = dr.getDecompiledFunction() != null
                    ? dr.getDecompiledFunction().getC() : null;
                collectTextCalls(c, ctx.texts, 0);
            }

            StringBuilder sb = new StringBuilder(4096);
            sb.append("    {\n      \"name\": ").append(q(f.getName()))
                .append(",\n      \"address\": \"").append(hex(f.getEntryPoint().getOffset()))
                .append("\",\n");
            if (!decompOk) sb.append("      \"decompiled\": false,\n");
            sb.append("      \"call_sites\": [");
            boolean first = true;
            for (Instruction ins : calls) {
                String site = dumpSite(f, ins, callOps, ctx);
                if (site == null) continue;
                if (!first) sb.append(",");
                first = false;
                sb.append("\n").append(site);
            }
            sb.append(first ? "]\n" : "\n      ]\n");
            sb.append("    }");
            return sb.toString();
        } catch (Exception e) {
            return null; // one bad function never kills the run
        }
    }

    // ---- per-call-site dump ----------------------------------------------
    private String dumpSite(Function f, Instruction ins, Map<Long, PcodeOp> callOps, FnCtx ctx) {
        long callAddr = ins.getAddress().getOffset();
        sites++;

        // callee: call reference -> function at target (thunk names carry
        // the import name, e.g. cJSON_GetString)
        String callee = null, calleeAddr = null;
        boolean thunk = false;
        for (Reference r : currentProgram.getReferenceManager()
                .getReferencesFrom(ins.getAddress())) {
            if (!r.getReferenceType().isCall() || r.getToAddress() == null) continue;
            Function tf = currentProgram.getFunctionManager().getFunctionAt(r.getToAddress());
            if (tf != null) {
                callee = tf.getName();
                calleeAddr = hex(r.getToAddress().getOffset());
                thunk = tf.isThunk();
            }
            break; // first call-type reference
        }
        boolean indirect = callee == null;
        if (indirect) indirectSites++;

        PcodeOp op = callOps.get(callAddr);
        boolean pcodeIndirect = op != null && op.getOpcode() == PcodeOp.CALLIND;
        // an indirect call whose pcode carries a constant target resolves too
        if (indirect && op != null && pcodeIndirect && op.getInput(0) != null
                && op.getInput(0).isConstant()) {
            Address tgt = parseAddr(Long.toHexString(op.getInput(0).getOffset()));
            Function tf = tgt == null ? null
                : currentProgram.getFunctionManager().getFunctionAt(tgt);
            if (tf != null) {
                callee = tf.getName();
                calleeAddr = hex(tgt.getOffset());
                thunk = tf.isThunk();
                indirect = false;
            }
        }

        // text join: same-name occurrence order over the combined queue —
        // resolved callees match either text form; unresolved indirect sites
        // fall back to order over the remaining PTR-form expressions
        String[] textArgs = null;
        String calleeHint = null;
        if (callee != null) {
            for (TextCall tc : ctx.texts) {
                if (tc.consumed || !tc.name.equals(callee)) continue;
                tc.consumed = true;
                textArgs = tc.args.toArray(new String[0]);
                textJoined++;
                break;
            }
        } else {
            for (TextCall tc : ctx.texts) {
                if (tc.consumed || !tc.indirect) continue;
                tc.consumed = true;
                textArgs = tc.args.toArray(new String[0]);
                // the PTR label is the decompiler's naming hint, not proof
                if (tc.name != null && !tc.name.isEmpty()) calleeHint = tc.name;
                break;
            }
        }

        // pcode arg inputs: skip input 0 (the call target varnode)
        List<Varnode> pcodeIns = new ArrayList<>();
        if (op != null && op.getInputs().length > 1) {
            for (int i = 1; i < op.getInputs().length && pcodeIns.size() < MAX_ARGS; i++) {
                pcodeIns.add(op.getInput(i));
            }
        }
        int arity = Math.max(pcodeIns.size(),
            textArgs != null ? Math.min(textArgs.length, MAX_ARGS) : 0);

        // the convention (callee's if known, else default) gives physical slots
        PrototypeModel cc = conventionFor(callee, calleeAddr);
        String retRegName = returnRegOf(cc);
        String binding = "none";
        if (pcodeIns.size() > 0 && textArgs != null) {
            binding = pcodeIns.size() == textArgs.length ? "pcode+text" : "positional-mismatch";
        } else if (pcodeIns.size() > 0) {
            binding = "pcode";
        } else if (textArgs != null) {
            binding = "text";
        }

        Address retSite = ins.getFallThrough();

        StringBuilder sb = new StringBuilder(1024);
        sb.append("        {\n");
        sb.append("          \"call\": \"").append(hex(callAddr)).append("\",\n");
        sb.append("          \"ret_site\": ").append(retSite != null
            ? "\"" + hex(retSite.getOffset()) + "\"" : "null").append(",\n");
        sb.append("          \"callee\": ").append(callee != null ? q(callee) : "null")
            .append(",\n");
        sb.append("          \"callee_addr\": ").append(calleeAddr != null
            ? "\"" + calleeAddr + "\"" : "null").append(",\n");
        if (indirect) sb.append("          \"indirect\": true,\n");
        if (thunk) sb.append("          \"thunk\": true,\n");
        if (calleeHint != null) {
            sb.append("          \"callee_hint\": ").append(q(calleeHint)).append(",\n");
        }

        // ---- args ----
        sb.append("          \"args\": [");
        for (int pos = 0; pos < arity; pos++) {
            if (pos > 0) sb.append(",");
            sb.append("\n            {");
            sb.append("\"pos\": ").append(pos);
            // physical slot from the calling-convention model
            VariableStorage st = argLoc(cc, pos);
            String loc = null, kind = "register";
            if (st != null && !st.isUnassignedStorage()) {
                if (st.isRegisterStorage() && st.getFirstVarnode() != null) {
                    loc = "$" + regNameOf(st.getFirstVarnode());
                } else if (st.isStackStorage()) {
                    int off = st.getStackOffset();
                    loc = "$sp" + (off >= 0 ? "+0x" + Integer.toHexString(off)
                        : "-0x" + Integer.toHexString(-off));
                    kind = "stack";
                }
            }
            if (loc == null && pos < pcodeIns.size()) {
                // convention gave nothing; the pcode varnode is the fallback
                Varnode vn = pcodeIns.get(pos);
                if (vn.isRegister()) loc = "$" + regNameOf(vn);
                else if (vn.getAddress().getAddressSpace().getName().equals("stack")) {
                    long off = vn.getOffset();
                    loc = "$sp" + (off >= 0 ? "+0x" + Long.toHexString(off)
                        : "-0x" + Long.toHexString(-off));
                    kind = "stack";
                }
            }
            sb.append(", \"loc\": ").append(loc != null ? q(loc) : "null");
            sb.append(", \"kind\": ").append(q(kind));
            // values: pcode const first, then text
            String constString = null, constAddr = null;
            Long constInt = null, vnConst = null;
            if (pos < pcodeIns.size()) {
                Varnode vn = pcodeIns.get(pos);
                sb.append(", \"vn\": ").append(q(vnDesc(vn)));
                if (vn.isConstant()) {
                    vnConst = vn.getOffset();
                } else if (vn.getAddress().getAddressSpace() == space) {
                    constString = stringAt(vn.getAddress());
                    if (constString == null) constAddr = hex(vn.getOffset());
                }
            }
            if (pos < (textArgs != null ? textArgs.length : 0)) {
                String t = textArgs[pos];
                sb.append(", \"text\": ").append(q(cap(t)));
                Object v = constInt == null && constString == null
                    ? resolveTextValue(t) : null;
                if (v instanceof String) constString = (String) v;
                else if (v instanceof long[]) {
                    constAddr = hex(((long[]) v)[0]);
                } else if (v instanceof Long) constInt = (Long) v;
            }
            if (vnConst != null && constInt == null) constInt = vnConst;
            if (constString != null) { sb.append(", \"const_string\": ").append(q(constString)); constArgs++; }
            if (constInt != null) sb.append(", \"const_int\": ").append(constInt);
            if (constAddr != null) sb.append(", \"const_addr\": \"").append(constAddr).append("\"");
            sb.append("}");
        }
        sb.append(arity > 0 ? "\n          ],\n" : "],\n");
        sb.append("          \"binding\": ").append(q(binding)).append(",\n");

        // ---- ret ----
        boolean retUsed = op != null && op.getOutput() != null;
        sb.append("          \"ret\": {\"reg\": ").append(retRegName != null
            ? q("$" + retRegName) : "null");
        sb.append(", \"used\": ").append(retUsed);
        if (op != null && op.getOutput() != null) {
            sb.append(", \"out_vn\": ").append(q(vnDesc(op.getOutput())));
        }
        List<String> consumers = retRegName != null && retSite != null
            ? consumers(f, retSite, retRegName) : null;
        if (consumers != null && !consumers.isEmpty()) {
            sb.append(", \"consumers\": [");
            for (int i = 0; i < consumers.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\n            ").append(consumers.get(i));
            }
            sb.append("\n          ]");
        }
        sb.append("}\n        }");
        return sb.toString();
    }

    // ---- consumers: bounded forward scan of raw pcode --------------------
    private List<String> consumers(Function f, Address retSite, String retRegName) {
        List<String> out = new ArrayList<>();
        Address cur = retSite;
        for (int i = 0; i < CONSUMER_WINDOW && cur != null; i++) {
            Instruction ins = currentProgram.getListing().getInstructionAt(cur);
            if (ins == null || !f.getBody().contains(cur)) break;
            PcodeOp[] ops = ins.getPcode();
            boolean reads = false, writes = false, stop = false, isCall =
                ins.getFlowType().isCall();
            for (PcodeOp op : ops) {
                if (opReadsReg(op, retRegName)) {
                    reads = true;
                    switch (op.getOpcode()) {
                        case PcodeOp.STORE:
                            out.add(rec(ins, "store",
                                renderDest(ops, op.getInput(1))));
                            break;
                        case PcodeOp.LOAD:
                            out.add(rec(ins, "deref", outRegName(op)));
                            break;
                        case PcodeOp.COPY:
                            out.add(rec(ins, "move", outRegName(op)));
                            break;
                        case PcodeOp.CALL:
                        case PcodeOp.CALLIND:
                            out.add(rec(ins, "passed-to-call", null));
                            break;
                        default:
                            out.add(rec(ins, "use",
                                isValueOp(op.getOpcode()) ? outRegName(op) : null));
                            break;
                    }
                }
                if (op.getOpcode() != PcodeOp.STORE && opWritesReg(op, retRegName)) {
                    writes = true;
                }
            }
            if (isCall && !reads) {
                // any intervening call clobbers caller-saved return registers
                out.add(rec(ins, "clobber-at-call", null));
                stop = true;
            }
            if (writes) {
                out.add(rec(ins, reads ? "consume-overwrite" : "clobber", null));
                stop = true;
            }
            if (stop) break;
            cur = ins.getFallThrough();
        }
        consumerCount += out.size();
        return out;
    }

    /**
     * value-producing pcode ops — used to decide whether a "use" consumer
     * may report the register it writes (comparison ops write flag
     * registers; reporting those as destinations is noise)
     */
    private static boolean isValueOp(int opcode) {
        switch (opcode) {
            case PcodeOp.INT_ADD:
            case PcodeOp.INT_SUB:
            case PcodeOp.INT_MULT:
            case PcodeOp.INT_DIV:
            case PcodeOp.INT_AND:
            case PcodeOp.INT_OR:
            case PcodeOp.INT_XOR:
            case PcodeOp.INT_LEFT:
            case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_2COMP:
            case PcodeOp.INT_NEGATE:
            case PcodeOp.PIECE:
            case PcodeOp.CAST:
                return true;
            default:
                return false;
        }
    }

    private String rec(Instruction ins, String kind, String to) {
        StringBuilder sb = new StringBuilder(96);
        sb.append("{\"at\": \"").append(hex(ins.getAddress().getOffset()))
            .append("\", \"kind\": ").append(q(kind));
        if (to != null) sb.append(", \"to\": ").append(q(to));
        return sb.append("}").toString();
    }

    private boolean opReadsReg(PcodeOp op, String regName) {
        for (Varnode in : op.getInputs()) {
            if (in.isRegister() && regNameOf(in).equals(regName)) return true;
        }
        return false;
    }

    private boolean opWritesReg(PcodeOp op, String regName) {
        Varnode out = op.getOutput();
        return out != null && out.isRegister() && regNameOf(out).equals(regName);
    }

    private String outRegName(PcodeOp op) {
        Varnode out = op.getOutput();
        return out != null && out.isRegister() ? "$" + regNameOf(out) : null;
    }

    /** STORE destination rendered from the INT_ADD/SUB feeding its address */
    private String renderDest(PcodeOp[] ops, Varnode dest) {
        if (dest == null) return null;
        String sp = dest.getAddress().getAddressSpace().getName();
        if (sp.equals("stack")) {
            long off = dest.getOffset();
            return "$sp" + (off >= 0 ? "+0x" + Long.toHexString(off)
                : "-0x" + Long.toHexString(-off));
        }
        if (sp.equals("register")) return "$" + regNameOf(dest);
        if (dest.getAddress().getAddressSpace() == space) {
            return hex(dest.getOffset());
        }
        if (sp.equals("unique")) {
            for (PcodeOp op : ops) {
                Varnode o = op.getOutput();
                if (o == null || !o.equals(dest)) continue;
                if (op.getOpcode() == PcodeOp.INT_ADD
                    || op.getOpcode() == PcodeOp.INT_SUB
                    || op.getOpcode() == PcodeOp.PTRADD) {
                    Varnode a = op.getInput(0), b = op.getInput(1);
                    String reg = null;
                    long k = 0;
                    if (a != null && a.isRegister()) reg = regNameOf(a);
                    if (b != null && b.isConstant()) k = b.getOffset();
                    if (reg == null && b != null && b.isRegister()) {
                        reg = regNameOf(b);
                        if (a != null && a.isConstant()) k = a.getOffset();
                    }
                    if (reg != null) {
                        boolean sub = op.getOpcode() == PcodeOp.INT_SUB;
                        return "$" + reg + (sub ? "-" : "+") + "0x"
                            + Long.toHexString(k);
                    }
                }
                if (op.getOpcode() == PcodeOp.COPY) {
                    return renderDest(ops, op.getInput(0));
                }
                return null;
            }
        }
        return null;
    }

    // ---- conventions -----------------------------------------------------
    private PrototypeModel conventionFor(String callee, String calleeAddr) {
        if (calleeAddr != null) {
            try {
                Function tf = currentProgram.getFunctionManager()
                    .getFunctionAt(space.getAddress(calleeAddr));
                if (tf != null && tf.getCallingConvention() != null) {
                    return tf.getCallingConvention();
                }
            } catch (Exception ignore) { /* fall to default */ }
        }
        return defaultCC;
    }

    private String returnRegOf(PrototypeModel cc) {
        try {
            VariableStorage st = cc.getReturnLocation(wordType, currentProgram);
            if (st != null && st.isRegisterStorage() && st.getFirstVarnode() != null) {
                return regNameOf(st.getFirstVarnode());
            }
        } catch (Exception ignore) { /* unknown */ }
        return null;
    }

    private VariableStorage argLoc(PrototypeModel cc, int pos) {
        Map<Integer, VariableStorage> m = locCache.computeIfAbsent(
            cc.getName(), k -> new HashMap<>());
        VariableStorage st = m.get(pos);
        if (st == null) {
            try {
                st = cc.getArgLocation(pos, new Parameter[0], wordType, currentProgram);
                m.put(pos, st);
            } catch (Exception e) {
                m.put(pos, null);
                return null;
            }
        }
        return st;
    }

    // ---- text parsing ----------------------------------------------------
    private static final class TextCall {
        final String name;
        final List<String> args;
        final boolean indirect; // the (*(code *)PTR_label_slot)(args) form
        boolean consumed;
        TextCall(String name, List<String> args, boolean indirect) {
            this.name = name;
            this.args = args;
            this.indirect = indirect;
        }
    }

    private void collectTextCalls(String c, List<TextCall> out, int depth) {
        if (c == null || depth > 4) return;
        // direct call form: identifier(args), paren-depth aware; nested
        // calls inside the argument text are collected recursively
        int i = 0, n = c.length();
        while (i < n) {
            char ch = c.charAt(i);
            if (ch == '"') { i = skipQuoted(c, i, '"'); continue; }
            if (ch == '\'') { i = skipQuoted(c, i, '\''); continue; }
            if (Character.isJavaIdentifierStart(ch)) {
                int j = i + 1;
                while (j < n && Character.isJavaIdentifierPart(c.charAt(j))) j++;
                String name = c.substring(i, j);
                int k = j;
                while (k < n && c.charAt(k) == ' ') k++;
                if (k < n && c.charAt(k) == '(' && !CALL_KEYWORDS.contains(name)) {
                    int close = matchingParen(c, k);
                    if (close > k) {
                        String inner = c.substring(k + 1, close);
                        out.add(new TextCall(name, splitArgs(inner), false));
                        collectTextCalls(inner, out, depth + 1);
                        i = close + 1;
                        continue;
                    }
                }
                i = j;
                continue;
            }
            i++;
        }
        // indirect form: (*(code *)PTR_label_slot)(args) — the MIPS/GOT
        // idiom; keyed by the PTR label so resolved callees can join it
        Matcher m = CALL_IND_RE.matcher(c);
        while (m.find()) {
            out.add(new TextCall(m.group(1), splitArgs(m.group(3)), true));
        }
    }

    private int skipQuoted(String c, int i, char q) {
        int n = c.length();
        i++;
        while (i < n) {
            if (c.charAt(i) == '\\') { i += 2; continue; }
            if (c.charAt(i) == q) return i + 1;
            i++;
        }
        return n;
    }

    private int matchingParen(String c, int open) {
        int n = c.length(), depth = 0, i = open;
        while (i < n) {
            char ch = c.charAt(i);
            if (ch == '"' || ch == '\'') { i = skipQuoted(c, i, ch); continue; }
            if (ch == '(') depth++;
            else if (ch == ')') {
                depth--;
                if (depth == 0) return i;
            }
            i++;
        }
        return -1;
    }

    private List<String> splitArgs(String inner) {
        List<String> out = new ArrayList<>();
        int n = inner.length(), depth = 0, start = 0;
        for (int i = 0; i < n; i++) {
            char ch = inner.charAt(i);
            if (ch == '"' || ch == '\'') { i = skipQuoted(inner, i, ch) - 1; continue; }
            if (ch == '(') depth++;
            else if (ch == ')') depth--;
            else if (ch == ',' && depth == 0) {
                out.add(inner.substring(start, i).trim());
                start = i + 1;
            }
        }
        if (n > start) out.add(inner.substring(start, n).trim());
        return out;
    }

    // ---- text value resolution -------------------------------------------
    /** const String, Long (int), long[1] (address) or null (dynamic). */
    private Object resolveTextValue(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        String s = raw.trim();
        while (true) {
            // strip casts: (char *), (tm *), (undefined4) ... — only when
            // something follows (a cast always wraps an expression)
            Matcher cm = CAST_PREFIX.matcher(s);
            if (cm.find() && cm.start() == 0 && cm.end() < s.length()) {
                s = s.substring(cm.end()).trim();
                continue;
            }
            // strip one balanced parenthesized wrapper: (DAT_x + 0xc)
            if (s.length() > 1 && s.charAt(0) == '('
                    && matchingParen(s, 0) == s.length() - 1) {
                s = s.substring(1, s.length() - 1).trim();
                continue;
            }
            break;
        }
        if (s.isEmpty()) return null;
        Matcher lit = STR_LIT.matcher(s);
        if (lit.find() && lit.start() == 0 && lit.end() == s.length()) {
            return unescape(lit.group(1));
        }
        if (s.matches("-?0x[0-9a-fA-F]+") || s.matches("-?\\d+")) {
            try { return Long.decode(s); } catch (Exception e) { return null; }
        }
        Matcher dat = DAT_ARITH.matcher(s);
        if (dat.find() && dat.start() == 0 && dat.end() == s.length()) {
            Long p = readPointer(parseAddr(dat.group(1)));
            if (p == null) return null;
            long v = p + datSigned(dat);
            return derefResult(v);
        }
        Matcher rev = DAT_ARITH_REV.matcher(s);
        if (rev.find() && rev.start() == 0 && rev.end() == s.length()) {
            Long p = readPointer(parseAddr(rev.group(2)));
            if (p == null) return null;
            return derefResult(p + Long.parseLong(rev.group(1), 16));
        }
        Matcher ptr = PTR_ARITH.matcher(s);
        if (ptr.find() && ptr.start() == 0 && ptr.end() == s.length()) {
            Long p = readPointer(parseAddr(ptr.group(2)));
            if (p == null) return null;
            long off = 0;
            if (ptr.group(5) != null) {
                off = Long.parseLong(ptr.group(5), 16);
                if ("-".equals(ptr.group(3)) || "-".equals(ptr.group(4))) off = -off;
            }
            return derefResult(p + off);
        }
        return null;
    }

    private long datSigned(Matcher dat) {
        if (dat.group(2) == null || dat.group(3) == null) return 0;
        long k = Long.parseLong(dat.group(3), 16);
        return "-".equals(dat.group(2)) ? -k : k;
    }

    private Object derefResult(long addr) {
        try {
            String str = stringAt(space.getAddress(hex(addr)));
            if (str != null) return str;
        } catch (Exception ignore) { /* out of address space */ }
        return new long[]{addr};
    }

    private Address parseAddr(String hexDigits) {
        try {
            return space.getAddress("0x" + hexDigits);
        } catch (Exception e) {
            return null;
        }
    }

    private String unescape(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case 'n': b.append('\n'); break;
                    case 't': b.append('\t'); break;
                    case 'r': b.append('\r'); break;
                    case '\\': b.append('\\'); break;
                    case '"': b.append('"'); break;
                    case '\'': b.append('\''); break;
                    default: b.append(n);
                }
            } else {
                b.append(ch);
            }
        }
        return b.toString();
    }

    // ---- memory helpers (proven on this corpus) ---------------------------
    private Long readPointer(Address a) {
        if (a == null) return null;
        try {
            if (ptrSize >= 8) return memory.getLong(a);
            return (long) memory.getInt(a) & 0xffffffffL;
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    private String definedStringAt(Address a) {
        if (a == null) return null;
        Data d = currentProgram.getListing().getDataAt(a);
        if (d != null && d.hasStringValue()) return (String) d.getValue();
        return null;
    }

    private String stringAt(Address a) {
        if (a == null) return null;
        String s = definedStringAt(a);
        if (s != null) return s;
        try {
            byte[] buf = new byte[STR_MAX];
            memory.getBytes(a, buf);
            int n = 0;
            while (n < STR_MAX && buf[n] != 0 && buf[n] >= 0x20 && buf[n] < 0x7f) n++;
            if (n >= 2) return new String(buf, 0, n, StandardCharsets.US_ASCII);
        } catch (MemoryAccessException e) { /* unmapped */ }
        return null;
    }

    // ---- small utilities ---------------------------------------------------
    private List<Instruction> callInstructions(Function f) {
        List<Instruction> out = new ArrayList<>();
        for (Instruction ins : currentProgram.getListing()
                .getInstructions(f.getBody(), true)) {
            if (ins.getFlowType().isCall()) out.add(ins);
        }
        return out;
    }

    private String regNameOf(Varnode vn) {
        Register r = currentProgram.getLanguage()
            .getRegister(vn.getAddress(), vn.getSize());
        return r != null ? r.getName() : "reg_" + hex(vn.getAddress().getOffset());
    }

    private String vnDesc(Varnode vn) {
        if (vn == null) return "null";
        String sp = vn.getAddress().getAddressSpace().getName();
        if (sp.equals("register")) return regNameOf(vn);
        if (sp.equals("stack")) {
            long off = vn.getOffset();
            return "$sp" + (off >= 0 ? "+0x" + Long.toHexString(off)
                : "-0x" + Long.toHexString(-off));
        }
        if (sp.equals("unique")) return "unique:0x" + Long.toHexString(vn.getOffset());
        if (vn.isConstant()) return "#" + vn.getOffset();
        return hex(vn.getOffset());
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    private static String cap(String s) {
        if (s == null) return null;
        return s.length() <= TEXT_MAX ? s : s.substring(0, TEXT_MAX);
    }

    /** JSON string escape (control chars, quotes, backslash) */
    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 8);
        b.append('"');
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (ch < 0x20 || ch > 0x7e) {
                        b.append(String.format("\\u%04x", (int) ch));
                    } else {
                        b.append(ch);
                    }
            }
        }
        return b.append('"').toString();
    }
}
