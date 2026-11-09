// Exports a per-function xref index (referenced strings + call edges) as JSON.
//
// Usage: analyzeHeadless <projDir> <projName> -import <binary> \
//          -scriptPath <dir> -postScript IndexExporter.java <out.json>
//        (re-export from a cached project: -process <name> -noanalysis ...)
//
// ARCHITECTURE-NEUTRAL by design — three evidence paths, unioned, because
// vendor compilers on this corpus encode .rodata access differently:
//   1. reference-manager: an instruction's direct reference to a defined
//      string (or a pointer whose pointee is a string) — the common case,
//      works on every architecture
//   2. decompiler arithmetic: PIC expressions the analyzer never typed,
//      e.g. `DAT_00048e90 + 0x48914` — the pool slot holds a base value,
//      base + const IS the string address (evaluated against program
//      memory; pointer width follows the program's default pointer size,
//      so 32- and 64-bit both resolve)
//   3. decompiler text calls: calls rendered as `callee(expr, ...)`. The
//      argument expressions are resolved with the same DAT arithmetic —
//      this recovers per-callsite argument strings (parameter names) even
//      when the loads carry no references at all
//
// Output per (non-external) function:
//   { name, address, thunk?,
//     call_sites: [{to, to_address, address, args}]   — ref-manager calls,
//       args = strings referenced by instructions just before the call
//     text_calls:  [{to, args}]                        — decompiled call
//       expressions with resolved argument strings (no address: the C text
//       carries none; match on (caller, callee))
//     callers: [{name, address}]
//     strings: [value ...] }
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;

public class IndexExporter extends GhidraScript {

    // instructions before a call whose string refs count as call args
    private static final int ARG_WINDOW = 16;
    private static final int MAX_ARGS = 8;
    private static final int STR_MAX = 96;
    private static final int DECOMPILE_TIMEOUT = 60;

    // DAT_00048e90 (+|- 0x48914)  and  0x48914 + DAT_00048e90   — ARM PIC
    private static final Pattern DAT_ARITH = Pattern.compile(
        "DAT_([0-9a-f]+)\\s*(?:([+\\-])\\s*0x([0-9a-f]+))?");
    private static final Pattern DAT_ARITH_REV = Pattern.compile(
        "0x([0-9a-f]+)\\s*\\+\\s*DAT_([0-9a-f]+)");
    // PTR_<label>_<slothex> (± 0xoff) — the MIPS/ELF-DYN idiom: GOT slots
    // ("PTR_getenv_00084a04", "PTR_s_Extended_0006fff8+8_00084128") whose
    // value (applied relocation) is the base; base +/- off is the string.
    // The label is GREEDY so the trailing _<hex> group is the SLOT address,
    // never an address embedded mid-label; offsets allow the compound
    // "+ -0x6020" form the decompiler emits.
    private static final Pattern PTR_ARITH = Pattern.compile(
        "\\bPTR_([A-Za-z0-9_.+-]*[A-Za-z0-9_.+])_([0-9a-f]{4,})(?![A-Za-z0-9_.+-])"
        + "(?:\\s*([+\\-])\\s*(?:([+\\-])\\s*)?0x([0-9a-f]+))?");
    // indirect call in decompiled C: (*(code *)PTR_callee_00084a04)(args)
    private static final Pattern CALL_IND_RE = Pattern.compile(
        "\\(\\*\\(code\\s*\\*\\)\\s*PTR_([A-Za-z0-9_.+-]*?)_([0-9a-f]{4,})\\)"
        + "\\s*\\(([^;]{0,400}?)\\)");
    // call expression in decompiled C: callee(args)
    private static final Pattern CALL_RE = Pattern.compile(
        "\\b([A-Za-z_][A-Za-z0-9_]*)\\s*\\(([^;]{0,400}?)\\)");
    private static final Set<String> CALL_KEYWORDS = Set.of(
        "if", "for", "while", "switch", "return", "sizeof", "else", "do",
        "case", "default", "goto", "break", "continue", "defined", "undef");

    private Memory memory;
    private ghidra.program.model.listing.Listing listing;
    private ghidra.program.model.symbol.ReferenceManager refman;
    private ghidra.program.model.listing.FunctionManager funcman;
    private AddressSpace space;
    private int ptrSize;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("IndexExporter: missing output path argument");
            return;
        }
        String outPath = args[0];
        memory = currentProgram.getMemory();
        listing = currentProgram.getListing();
        refman = currentProgram.getReferenceManager();
        funcman = currentProgram.getFunctionManager();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        ptrSize = currentProgram.getDefaultPointerSize();

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        int nfun = 0, nstr = 0, ncall = 0, ndec = 0, ntext = 0;
        StringBuilder sb = new StringBuilder(1 << 20);
        sb.append("{\n\"binary\": ").append(q(currentProgram.getName()))
          .append(",\n\"functions\": [\n");

        FunctionIterator it = funcman.getFunctions(true);
        boolean firstFun = true;
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal()) {
                continue;
            }

            Set<String> strings = new LinkedHashSet<>();
            List<long[]> callSites = new ArrayList<>(); // {callAddr, toAddr}
            collectRefs(f, strings, callSites);

            List<Object[]> textCalls = new ArrayList<>(); // {callee, argsList}
            String c = decompileOf(dec, f);
            if (c != null) {
                ndec++;
                collectArithStrings(c, strings);
                ntext += collectTextCalls(c, textCalls);
            }
            nstr += strings.size();

            if (!firstFun) {
                sb.append(",\n");
            }
            firstFun = false;
            sb.append("{ \"name\": ").append(q(f.getName()))
              .append(", \"address\": \"").append(f.getEntryPoint()).append("\"");
            if (f.isThunk()) {
                sb.append(", \"thunk\": true");
            }

            sb.append(", \"call_sites\": [");
            boolean firstCs = true;
            for (long[] cs : callSites) {
                Address callAddr = addr(cs[0]);
                Address toAddr = addr(cs[1]);
                if (callAddr == null || toAddr == null) continue;
                Function to = funcman.getFunctionAt(toAddr);
                String toName = to != null ? to.getName() : primarySymbolName(toAddr);
                List<String> csArgs = argsNear(callAddr);
                ncall++;
                if (!firstCs) sb.append(", ");
                firstCs = false;
                sb.append("{ \"to\": ").append(q(toName))
                  .append(", \"to_address\": \"").append(toAddr).append("\"")
                  .append(", \"address\": \"").append(callAddr).append("\"")
                  .append(", \"args\": [");
                for (int i = 0; i < csArgs.size() && i < MAX_ARGS; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(q(csArgs.get(i)));
                }
                sb.append("] }");
            }

            sb.append("], \"text_calls\": [");
            boolean firstTc = true;
            for (Object[] tc : textCalls) {
                @SuppressWarnings("unchecked")
                List<String> tcArgs = (List<String>) tc[1];
                if (!firstTc) sb.append(", ");
                firstTc = false;
                sb.append("{ \"to\": ").append(q((String) tc[0]))
                  .append(", \"args\": [");
                for (int i = 0; i < tcArgs.size() && i < MAX_ARGS; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(q(tcArgs.get(i)));
                }
                sb.append("] }");
            }

            sb.append("], \"callers\": [");
            // sorted by address: getCallingFunctions() iterates a hash set,
            // whose order is not stable across runs — sorting makes the whole
            // index byte-reproducible
            List<Function> callers = new ArrayList<>(f.getCallingFunctions(monitor));
            callers.sort((x, y) -> x.getEntryPoint().compareTo(y.getEntryPoint()));
            boolean firstCa = true;
            for (Function cf : callers) {
                if (!firstCa) sb.append(", ");
                firstCa = false;
                sb.append("{ \"name\": ").append(q(cf.getName()))
                  .append(", \"address\": \"").append(cf.getEntryPoint()).append("\" }");
            }
            sb.append("], \"strings\": [");
            boolean firstS = true;
            for (String s : strings) {
                if (s.isEmpty()) continue;
                if (!firstS) sb.append(", ");
                firstS = false;
                sb.append(q(s));
            }
            sb.append("] }");
            nfun++;
        }
        sb.append("\n]\n}\n");
        dec.dispose();

        try (PrintWriter pw = new PrintWriter(outPath, "UTF-8")) {
            pw.print(sb);
        }
        println("IndexExporter: functions=" + nfun + " decompiled=" + ndec
                + " strings=" + nstr + " call_sites=" + ncall
                + " text_calls=" + ntext + " -> " + outPath);
    }

    // ---- path 1: reference manager -----------------------------------------

    private void collectRefs(Function f, Set<String> strings,
            List<long[]> callSites) {
        InstructionIterator it = listing.getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (Reference r : refman.getReferencesFrom(ins.getAddress())) {
                if (r.getToAddress() == null) continue;
                if (r.getReferenceType().isCall()) {
                    callSites.add(new long[] {
                        ins.getAddress().getOffset(),
                        r.getToAddress().getOffset() });
                    continue;
                }
                String s = resolveRefString(r.getToAddress());
                if (s != null) strings.add(s);
            }
        }
    }

    /** defined string at the target, or one pointer hop to one */
    private String resolveRefString(Address to) {
        String s = definedStringAt(to);
        if (s != null) return s;
        Data d = listing.getDataAt(to);
        if (d != null && d.getValue() instanceof Address) {
            return definedStringAt((Address) d.getValue());
        }
        return null;
    }

    // ---- path 2+3: decompiler text -----------------------------------------

    private String decompileOf(DecompInterface dec, Function f) {
        try {
            DecompileResults r = dec.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);
            if (r != null && r.decompileCompleted()
                    && r.getDecompiledFunction() != null) {
                return r.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            // decompiler failures are per-function, never fatal
        }
        return null;
    }

    /** every DAT_x (+|- const) / const + DAT_x / PTR_lbl_slot (± const)
     *  expression in the C text — both PIC idioms resolve to a string */
    private void collectArithStrings(String c, Set<String> strings) {
        Matcher m = DAT_ARITH.matcher(c);
        while (m.find()) {
            Address dat = parseHex(m.group(1));
            if (dat == null) continue;
            if (m.group(3) != null) {
                Long base = readPointer(dat);
                if (base == null) continue;
                long off = Long.parseLong(m.group(3), 16);
                long target = "+".equals(m.group(2)) ? base + off : base - off;
                String s = stringAt(addr(target));
                if (s != null) strings.add(s);
            } else {
                // bare DAT_x / &DAT_x: the slot itself, or its pointee
                String s = definedStringAt(dat);
                if (s == null) {
                    Long base = readPointer(dat);
                    if (base != null) s = definedStringAt(addr(base));
                }
                if (s != null) strings.add(s);
            }
        }
        Matcher mrev = DAT_ARITH_REV.matcher(c);
        while (mrev.find()) {
            Address dat = parseHex(mrev.group(2));
            Long base = dat == null ? null : readPointer(dat);
            if (base == null) continue;
            String s = stringAt(addr(base + Long.parseLong(mrev.group(1), 16)));
            if (s != null) strings.add(s);
        }
        Matcher ptr = PTR_ARITH.matcher(c);
        while (ptr.find()) {
            Address slot = parseHex(ptr.group(2));
            Long base = slot == null ? null : readPointer(slot);
            if (base == null) continue;
            String s;
            if (ptr.group(5) != null) {   // compound "+ -0x" / plain "± 0x"
                long off = Long.parseLong(ptr.group(5), 16);
                String sign1 = ptr.group(3);
                String sign2 = ptr.group(4);
                boolean neg = "-".equals(sign1) ^ "-".equals(sign2);
                s = stringAt(addr(neg ? base - off : base + off));
            } else {
                s = stringAt(addr(base));  // bare slot: its pointee
            }
            if (s != null) strings.add(s);
        }
    }

    /**
     * Call expressions `callee(arg, ...)` in the C text, keeping only those
     * where at least one argument resolves to a string (parameter names).
     * Returns the number of calls recorded.
     */
    @SuppressWarnings("unchecked")
    private int collectTextCalls(String c, List<Object[]> out) {
        Set<String> seen = new LinkedHashSet<>();
        int n = 0;
        // indirect calls first: (*(code *)PTR_callee_slot)(args) — the callee
        // name lives inside the GOT-slot label; plain CALL_RE cannot see it
        Matcher mi = CALL_IND_RE.matcher(c);
        while (mi.find()) {
            List<String> args = new ArrayList<>();
            for (String arg : splitArgs(mi.group(3))) {
                String s = resolveArgString(arg);
                if (s != null) args.add(s);
            }
            if (args.isEmpty()) continue;
            String key = mi.group(1) + "#" + String.join(",", args);
            if (seen.add(key)) {
                out.add(new Object[] { mi.group(1), args });
                n++;
            }
        }
        Matcher m = CALL_RE.matcher(c);
        while (m.find()) {
            String callee = m.group(1);
            if (CALL_KEYWORDS.contains(callee)) continue;
            List<String> args = new ArrayList<>();
            for (String arg : splitArgs(m.group(2))) {
                String s = resolveArgString(arg);
                if (s != null) args.add(s);
            }
            if (args.isEmpty()) continue;
            String key = callee + "#" + String.join(",", args);
            if (seen.add(key)) {
                out.add(new Object[] { callee, args });
                n++;
            }
        }
        return n;
    }

    /** top-level comma split (nesting-aware for inner casts/calls) */
    private static List<String> splitArgs(String argText) {
        List<String> parts = new ArrayList<>();
        int depth = 0, start = 0;
        for (int i = 0; i < argText.length(); i++) {
            char ch = argText.charAt(i);
            if (ch == '(') depth++;
            else if (ch == ')') depth--;
            else if (ch == ',' && depth == 0) {
                parts.add(argText.substring(start, i));
                start = i + 1;
            }
        }
        if (start < argText.length()) parts.add(argText.substring(start));
        return parts;
    }

    /** one argument expression -> its string constant, if any */
    private String resolveArgString(String arg) {
        // inline literal in the decompiled text
        Matcher lit = Pattern.compile("\"((?:[^\"\\\\]|\\\\.){1,96})\"").matcher(arg);
        if (lit.find()) {
            return lit.group(1);
        }
        // DAT_x ± const arithmetic (ARM PIC parameter names)
        Matcher m = DAT_ARITH.matcher(arg);
        if (m.find()) {
            Address dat = parseHex(m.group(1));
            if (dat == null) return null;
            if (m.group(3) != null) {
                Long base = readPointer(dat);
                if (base == null) return null;
                long off = Long.parseLong(m.group(3), 16);
                long target = "+".equals(m.group(2)) ? base + off : base - off;
                return stringAt(addr(target));
            }
            return definedStringAt(dat);
        }
        // PTR_lbl_slot ± const (MIPS GOT parameter names)
        Matcher p = PTR_ARITH.matcher(arg);
        if (p.find()) {
            Address slot = parseHex(p.group(2));
            Long base = slot == null ? null : readPointer(slot);
            if (base == null) return null;
            if (p.group(5) != null) {
                long off = Long.parseLong(p.group(5), 16);
                boolean neg = "-".equals(p.group(3)) ^ "-".equals(p.group(4));
                return stringAt(addr(neg ? base - off : base + off));
            }
            return stringAt(addr(base));
        }
        return null;
    }

    // ---- call-site instruction windows --------------------------------------

    /** strings referenced by the ARG_WINDOW instructions before the call */
    private List<String> argsNear(Address callAddr) {
        List<String> out = new ArrayList<>();
        Deque<String> window = new ArrayDeque<>();
        Instruction back = listing.getInstructionBefore(callAddr);
        int guard = ARG_WINDOW;
        while (back != null && guard-- > 0) {
            List<String> here = new ArrayList<>();
            for (Reference r : refman.getReferencesFrom(back.getAddress())) {
                if (r.getToAddress() == null || r.getReferenceType().isCall()) continue;
                String s = resolveRefString(r.getToAddress());
                if (s != null) here.add(s);
            }
            for (int i = here.size() - 1; i >= 0; i--) {  // keep instruction order
                window.addFirst(here.get(i));
                if (window.size() > MAX_ARGS) window.removeLast();
            }
            back = listing.getInstructionBefore(back.getAddress());
        }
        out.addAll(window);
        return out;
    }

    // ---- helpers -------------------------------------------------------------

    private String primarySymbolName(Address a) {
        ghidra.program.model.symbol.Symbol s =
            currentProgram.getSymbolTable().getPrimarySymbol(a);
        return s != null ? s.getName() : "sub_" + a;
    }

    private Address addr(long offset) {
        try {
            return space.getAddress(offset);
        } catch (Exception e) {
            return null;
        }
    }

    private Address parseHex(String hex) {
        try {
            return space.getAddress(hex);
        } catch (Exception e) {
            return null;
        }
    }

    /** raw pointer read following the program's pointer width */
    private Long readPointer(Address a) {
        try {
            if (ptrSize >= 8) {
                return memory.getLong(a);
            }
            return (long) memory.getInt(a) & 0xffffffffL;
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    /** string from defined data only (precise, no guessing) */
    private String definedStringAt(Address a) {
        if (a == null) return null;
        Data d = listing.getDataAt(a);
        if (d != null && d.hasStringValue()) {
            return (String) d.getValue();
        }
        return null;
    }

    /** defined string, else raw ASCII at the address (for computed targets) */
    private String stringAt(Address a) {
        if (a == null) return null;
        String s = definedStringAt(a);
        if (s != null) return s;
        return asciiAt(a, 2);
    }

    private String asciiAt(Address a, int minLen) {
        try {
            byte[] buf = new byte[STR_MAX];
            memory.getBytes(a, buf);
            int n = 0;
            while (n < STR_MAX && buf[n] != 0 && buf[n] >= 0x20 && buf[n] < 0x7f) {
                n++;
            }
            if (n >= minLen) {
                return new String(buf, 0, n, StandardCharsets.US_ASCII);
            }
        } catch (MemoryAccessException e) {
            // unmapped target — not a string
        }
        return null;
    }

    private static String q(String s) {
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
