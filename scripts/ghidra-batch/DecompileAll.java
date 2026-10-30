// Dumps pseudocode of every non-external function to an output directory.
// Usage: analyzeHeadless <projDir> <projName> -import <binary> \
//          -scriptPath <dir> -postScript DecompileAll.java <outdir> -deleteProject
import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outdir = new File(args.length > 0 ? args[0] : "/tmp/ghidra-decompiled");
        outdir.mkdirs();

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int ok = 0;
        int fail = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal()) {
                continue;
            }
            String name = f.getName();
            String entry = f.getEntryPoint().toString();
            File out = new File(outdir, name + "_" + entry.replace(":", "_") + ".c");
            PrintWriter pw = new PrintWriter(out, "UTF-8");
            try {
                pw.println("// " + name + " @ " + entry);
                DecompileResults r = dec.decompileFunction(f, 120, monitor);
                if (r != null && r.decompileCompleted()) {
                    pw.print(r.getDecompiledFunction().getC());
                    ok++;
                }
                else {
                    pw.println("// DECOMPILE FAILED: " +
                        (r != null ? r.getErrorMessage() : "no result"));
                    fail++;
                }
            }
            finally {
                pw.close();
            }
        }
        dec.dispose();
        println("DecompileAll: ok=" + ok + " fail=" + fail + " -> " + outdir.getAbsolutePath());
    }
}
