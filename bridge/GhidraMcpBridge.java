// Copyright 2026 Rafał Jackiewicz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Persistent command bridge used by the ghidra-mcp server. It is started by
// ghidra-mcp through analyzeHeadless and is not meant to be run by hand.
//
// Protocol (loopback TCP, one request at a time):
//   request : <token> TAB <command> { TAB <key>=<percent-encoded value> } LF
//   response: ("OK" | "ERR") SP <byte count> LF <UTF-8 payload>
//@category MCP

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.DefinedStringIterator;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.data.DataTypeParser;

public class GhidraMcpBridge extends GhidraScript {

	private final Map<String, Program> open = new LinkedHashMap<>(); // project path -> program
	private final Map<Program, DecompInterface> decompilers = new HashMap<>();
	private Program current;

	// ------------------------------------------------------------------ main loop

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("GhidraMcpBridge: missing run directory argument");
			return;
		}
		File runDir = new File(args[0]);
		String token = new String(Files.readAllBytes(new File(runDir, "token").toPath()),
			StandardCharsets.UTF_8).trim();

		try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
			File tmp = new File(runDir, "port.tmp");
			Files.write(tmp.toPath(),
				Integer.toString(server.getLocalPort()).getBytes(StandardCharsets.UTF_8));
			Files.move(tmp.toPath(), new File(runDir, "port").toPath(),
				StandardCopyOption.ATOMIC_MOVE);
			server.setSoTimeout(120000); // give up if ghidra-mcp never connects
			try (Socket s = server.accept()) {
				serve(s, token);
			}
		}
		finally {
			closeAll();
		}
	}

	private void serve(Socket s, String token) throws Exception {
		BufferedReader in =
			new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
		OutputStream out = s.getOutputStream();
		String line;
		while ((line = in.readLine()) != null) {
			String status = "OK";
			String payload;
			try {
				String[] parts = line.split("\t", -1);
				if (parts.length < 2 || !parts[0].equals(token)) {
					throw new IllegalArgumentException("bad request");
				}
				Map<String, String> a = new HashMap<>();
				for (int i = 2; i < parts.length; i++) {
					int eq = parts[i].indexOf('=');
					if (eq > 0) {
						a.put(parts[i].substring(0, eq), decode(parts[i].substring(eq + 1)));
					}
				}
				if (parts[1].equals("shutdown")) {
					reply(out, "OK", "bye");
					return;
				}
				payload = dispatch(parts[1], a);
			}
			catch (UserError e) {
				status = "ERR";
				payload = e.getMessage();
			}
			catch (Throwable t) {
				status = "ERR";
				StringWriter sw = new StringWriter();
				t.printStackTrace(new PrintWriter(sw));
				String[] trace = sw.toString().split("\n");
				StringBuilder sb = new StringBuilder(t.toString());
				for (int i = 1; i < Math.min(trace.length, 6); i++) {
					sb.append('\n').append(trace[i]);
				}
				payload = sb.toString();
			}
			reply(out, status, payload);
		}
	}

	private static void reply(OutputStream out, String status, String payload) throws Exception {
		byte[] body = (payload == null ? "" : payload).getBytes(StandardCharsets.UTF_8);
		out.write((status + " " + body.length + "\n").getBytes(StandardCharsets.UTF_8));
		out.write(body);
		out.flush();
	}

	private static String decode(String v) {
		if (v.indexOf('%') < 0) {
			return v;
		}
		java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
		byte[] src = v.getBytes(StandardCharsets.UTF_8);
		for (int i = 0; i < src.length; i++) {
			if (src[i] == '%' && i + 2 < src.length) {
				bo.write(Integer.parseInt(new String(src, i + 1, 2, StandardCharsets.US_ASCII), 16));
				i += 2;
			}
			else {
				bo.write(src[i]);
			}
		}
		return new String(bo.toByteArray(), StandardCharsets.UTF_8);
	}

	private static class UserError extends RuntimeException {
		UserError(String msg) {
			super(msg);
		}
	}

	private String dispatch(String cmd, Map<String, String> a) throws Exception {
		switch (cmd) {
			case "ping":
				return "pong";
			case "list_programs":
				return listPrograms();
			case "list_languages":
				return listLanguages(a);
			case "import_binary":
				return importBinary(a);
			case "open_program":
				return openProgramCmd(a);
			case "close_program":
				return closeProgramCmd(a);
			case "delete_program":
				return deleteProgram(a);
			case "analyze_program":
				return analyze(a);
			case "program_info":
				return programInfo(prog(a));
			case "list_functions":
				return listFunctions(a);
			case "function_info":
				return functionInfo(a);
			case "decompile_function":
				return decompile(a);
			case "disassemble":
				return disassembleCmd(a);
			case "list_strings":
				return listStrings(a);
			case "search_symbols":
				return searchSymbols(a);
			case "list_imports":
				return listImports(a);
			case "list_exports":
				return listExports(a);
			case "list_segments":
				return listSegments(a);
			case "xrefs_to":
				return xrefsTo(a);
			case "xrefs_from":
				return xrefsFrom(a);
			case "read_memory":
				return readMemory(a);
			case "search_bytes":
				return searchBytes(a);
			case "rename_function":
				return renameFunction(a);
			case "rename_variable":
				return renameVariable(a);
			case "set_function_signature":
				return setSignature(a);
			case "create_label":
				return createLabel(a);
			case "set_comment":
				return setComment(a);
			case "create_function":
				return createFunctionCmd(a);
			case "define_type":
				return defineType(a);
			case "set_variable_type":
				return setVariableType(a);
			case "set_data_type":
				return setDataType(a);
			default:
				throw new UserError("Unknown command: " + cmd);
		}
	}

	// ------------------------------------------------------------------ helpers

	private static String req(Map<String, String> a, String key) {
		String v = a.get(key);
		if (v == null || v.isEmpty()) {
			throw new UserError("Missing required argument '" + key + "'");
		}
		return v;
	}

	private static int intArg(Map<String, String> a, String key, int def, int min, int max) {
		String v = a.get(key);
		if (v == null || v.isEmpty()) {
			return def;
		}
		try {
			long n = v.startsWith("0x") || v.startsWith("0X") ? Long.parseLong(v.substring(2), 16)
					: (long) Double.parseDouble(v);
			return (int) Math.max(min, Math.min(max, n));
		}
		catch (NumberFormatException e) {
			throw new UserError("Argument '" + key + "' must be a number, got '" + v + "'");
		}
	}

	private static boolean boolArg(Map<String, String> a, String key, boolean def) {
		String v = a.get(key);
		if (v == null || v.isEmpty()) {
			return def;
		}
		return v.equalsIgnoreCase("true") || v.equals("1") || v.equalsIgnoreCase("yes");
	}

	private static boolean matches(String haystack, String needleLower) {
		return needleLower == null || needleLower.isEmpty() ||
			(haystack != null && haystack.toLowerCase(Locale.ROOT).contains(needleLower));
	}

	private static String lower(Map<String, String> a, String key) {
		String v = a.get(key);
		return v == null ? null : v.toLowerCase(Locale.ROOT);
	}

	/** Collects one page of a (possibly long) list and reports how much there is in total. */
	private static class Pager {
		final StringBuilder sb = new StringBuilder();
		final int offset, limit;
		int total;

		Pager(Map<String, String> a) {
			offset = intArg(a, "offset", 0, 0, Integer.MAX_VALUE);
			limit = intArg(a, "limit", 100, 1, 5000);
		}

		void add(String line) {
			if (total >= offset && total < offset + limit) {
				sb.append(line).append('\n');
			}
			total++;
		}

		String finish(String what) {
			if (total == 0) {
				return "No " + what + " found.";
			}
			int shown = Math.max(0, Math.min(total, offset + limit) - offset);
			sb.append("[").append(what).append(": showing ").append(shown).append(" of ")
					.append(total).append(", offset ").append(offset);
			if (offset + shown < total) {
				sb.append("; next page: offset=").append(offset + shown);
			}
			sb.append("]");
			return sb.toString();
		}
	}

	private void walk(DomainFolder folder, List<DomainFile> out) {
		for (DomainFile f : folder.getFiles()) {
			if (Program.class.isAssignableFrom(f.getDomainObjectClass())) {
				out.add(f);
			}
		}
		for (DomainFolder sub : folder.getFolders()) {
			walk(sub, out);
		}
	}

	private List<DomainFile> programFiles() {
		List<DomainFile> files = new ArrayList<>();
		walk(state.getProject().getProjectData().getRootFolder(), files);
		return files;
	}

	private DomainFile findFile(String name) {
		List<DomainFile> files = programFiles();
		for (DomainFile f : files) {
			if (f.getPathname().equals(name)) {
				return f;
			}
		}
		for (DomainFile f : files) {
			if (f.getName().equals(name)) {
				return f;
			}
		}
		for (DomainFile f : files) {
			if (f.getName().equalsIgnoreCase(name)) {
				return f;
			}
		}
		return null;
	}

	private Program openFile(DomainFile f) throws Exception {
		Program p = open.get(f.getPathname());
		if (p == null) {
			p = (Program) f.getDomainObject(this, true, false, monitor);
			open.put(f.getPathname(), p);
		}
		return p;
	}

	/** Resolves the program a command applies to: explicit "program" argument or the current one. */
	private Program prog(Map<String, String> a) throws Exception {
		String name = a.get("program");
		if (name != null && !name.isEmpty()) {
			DomainFile f = findFile(name);
			if (f == null) {
				throw new UserError("No program named '" + name +
					"' in the project. Use list_programs to see what is available.");
			}
			return openFile(f);
		}
		if (current == null) {
			List<DomainFile> files = programFiles();
			if (files.size() == 1) {
				current = openFile(files.get(0));
			}
			else if (files.isEmpty()) {
				throw new UserError(
					"The Ghidra project is empty. Import a binary first with import_binary.");
			}
			else {
				throw new UserError("No program is open. Call open_program first, or pass the " +
					"'program' argument. Available programs:\n" + listPrograms());
			}
		}
		return current;
	}

	private void releaseProgram(Program p) {
		DecompInterface d = decompilers.remove(p);
		if (d != null) {
			d.dispose();
		}
		p.release(this);
	}

	private void closeAll() {
		for (Program p : open.values()) {
			try {
				releaseProgram(p);
			}
			catch (Throwable t) {
				// keep closing the rest
			}
		}
		open.clear();
		current = null;
	}

	private Address addr(Program p, String text) {
		if (text == null || text.trim().isEmpty()) {
			throw new UserError("An address or symbol name is required");
		}
		String t = text.trim();
		boolean looksNumeric = t.startsWith("0x") || t.startsWith("0X") || t.indexOf(':') >= 0;
		if (!looksNumeric) {
			SymbolIterator it = p.getSymbolTable().getSymbols(t);
			if (it.hasNext()) {
				return it.next().getAddress();
			}
		}
		Address a = null;
		try {
			a = p.getAddressFactory().getAddress(t);
		}
		catch (Exception e) {
			// fall through
		}
		if (a == null) {
			throw new UserError("Cannot resolve '" + text + "' to an address or symbol in " +
				p.getName() + ". Use a hex address such as 0x401000 or an exact symbol name.");
		}
		return a;
	}

	private Function func(Program p, String text) {
		if (text == null || text.trim().isEmpty()) {
			throw new UserError("A function name or address is required");
		}
		String t = text.trim();
		boolean looksNumeric = t.startsWith("0x") || t.startsWith("0X");
		if (!looksNumeric) {
			Function external = null;
			for (Symbol s : p.getSymbolTable().getSymbols(t)) {
				if (s.getSymbolType() == SymbolType.FUNCTION) {
					Function f = (Function) s.getObject();
					if (f != null && !f.isExternal()) {
						return f;
					}
					if (f != null) {
						external = f;
					}
				}
			}
			if (t.contains("::")) {
				for (Function f : p.getFunctionManager().getFunctions(true)) {
					if (f.getName(true).equals(t)) {
						return f;
					}
				}
			}
			if (external != null) {
				return external;
			}
		}
		Address a;
		try {
			a = addr(p, t);
		}
		catch (UserError e) {
			throw new UserError("No function named '" + text + "' in " + p.getName() +
				". Use list_functions (with a filter) to find it.");
		}
		Function f = p.getFunctionManager().getFunctionContaining(a);
		if (f == null) {
			throw new UserError("No function contains address " + a +
				". Use create_function to define one there.");
		}
		return f;
	}

	private interface Change {
		String apply() throws Exception;
	}

	/** Runs a modification inside a transaction and saves the program when it succeeds. */
	private String modify(Program p, String what, Change c) throws Exception {
		int tx = p.startTransaction("ghidra-mcp: " + what);
		boolean ok = false;
		String result;
		try {
			result = c.apply();
			ok = true;
		}
		finally {
			p.endTransaction(tx, ok);
		}
		if (p.getDomainFile().isInWritableProject() && p.isChanged()) {
			p.save("ghidra-mcp: " + what, monitor);
		}
		return result;
	}

	private DecompInterface decompiler(Program p) {
		DecompInterface d = decompilers.get(p);
		if (d == null) {
			d = new DecompInterface();
			d.setOptions(new DecompileOptions());
			if (!d.openProgram(p)) {
				throw new UserError("Decompiler failed to start: " + d.getLastMessage());
			}
			decompilers.put(p, d);
		}
		return d;
	}

	private DecompileResults decompileFn(Program p, Function f, int timeout) {
		DecompileResults r = decompiler(p).decompileFunction(f, timeout, monitor);
		if (r == null || !r.decompileCompleted()) {
			throw new UserError("Decompilation of " + f.getName() + " failed: " +
				(r == null ? "no result" : r.getErrorMessage()));
		}
		return r;
	}

	private static String fnLine(Function f) {
		return f.getEntryPoint() + "  " + f.getName(true) +
			(f.isThunk() ? "  [thunk]" : "") + (f.isExternal() ? "  [external]" : "");
	}

	// ------------------------------------------------------------------ project

	private String listPrograms() {
		List<DomainFile> files = programFiles();
		if (files.isEmpty()) {
			return "The Ghidra project is empty. Import a binary with import_binary.";
		}
		StringBuilder sb = new StringBuilder();
		for (DomainFile f : files) {
			Program p = open.get(f.getPathname());
			sb.append(f.getPathname());
			if (p != null) {
				sb.append(p == current ? "  [open, current]" : "  [open]");
			}
			sb.append('\n');
		}
		return sb.toString().trim();
	}

	private String listLanguages(Map<String, String> a) {
		String filter = lower(a, "filter");
		Pager pg = new Pager(a);
		Set<String> lines = new TreeSet<>();
		for (LanguageDescription d : DefaultLanguageService.getLanguageService()
				.getLanguageDescriptions(false)) {
			StringBuilder cs = new StringBuilder();
			d.getCompatibleCompilerSpecDescriptions().forEach(c -> {
				cs.append(cs.length() == 0 ? "" : ",").append(c.getCompilerSpecID());
			});
			String line = d.getLanguageID() + "  (" + d.getDescription() + "; compilers: " + cs + ")";
			if (matches(line, filter)) {
				lines.add(line);
			}
		}
		for (String l : lines) {
			pg.add(l);
		}
		return pg.finish("languages");
	}

	private String importBinary(Map<String, String> a) throws Exception {
		File file = new File(req(a, "path"));
		if (!file.isFile()) {
			throw new UserError("File not found on the Ghidra host: " + file +
				"\nimport_binary reads paths on the machine where ghidra-mcp runs. If the file " +
				"lives on another machine, upload it first with the prepare_upload tool and " +
				"import the path returned by the upload.");
		}
		String language = a.get("language");
		String compiler = a.get("compiler");
		String base = a.get("base_address");
		boolean raw = boolArg(a, "raw_binary", base != null && !base.isEmpty());
		boolean hasLanguage = language != null && !language.isEmpty();
		if (raw && !hasLanguage) {
			throw new UserError("Raw binary import needs 'language' (for example " +
				"ARM:LE:32:Cortex or x86:LE:64:default). Use list_languages to find the ID.");
		}

		MessageLog log = new MessageLog();
		ProgramLoader.Builder b = ProgramLoader.builder()
				.source(file)
				.project(state.getProject())
				.log(log)
				.monitor(monitor);
		if (a.get("name") != null && !a.get("name").isEmpty()) {
			b.name(a.get("name"));
		}
		if (hasLanguage) {
			b.language(language);
			if (compiler != null && !compiler.isEmpty()) {
				b.compiler(compiler);
			}
		}
		if (raw) {
			b.loaders(BinaryLoader.class);
			if (base != null && !base.isEmpty()) {
				b.addLoaderArg("-loader-baseAddr", base);
			}
		}

		Program p;
		String path;
		try (LoadResults<Program> results = b.load()) {
			results.save(monitor);
			p = results.getPrimaryDomainObject(this);
			path = p.getDomainFile().getPathname();
		}
		catch (LoadException e) {
			throw new UserError("Ghidra could not identify the format of " + file.getName() +
				" (" + e.getMessage() + "). For raw firmware or shellcode pass 'language' and " +
				"'base_address' to import it as a raw binary.");
		}
		open.put(path, p);
		current = p;

		StringBuilder sb = new StringBuilder();
		sb.append("Imported ").append(file.getName()).append(" as ").append(path).append('\n');
		if (boolArg(a, "analyze", true)) {
			sb.append(runAnalysis(p)).append('\n');
		}
		else {
			sb.append("Auto-analysis skipped; run analyze_program before decompiling.\n");
		}
		sb.append(programInfo(p));
		return sb.toString();
	}

	private String runAnalysis(Program p) throws Exception {
		long t0 = System.currentTimeMillis();
		modify(p, "auto-analysis", () -> {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
			mgr.initializeOptions();
			mgr.reAnalyzeAll(null);
			mgr.startAnalysis(monitor);
			GhidraProgramUtilities.markProgramAnalyzed(p);
			return "";
		});
		return "Auto-analysis finished in " + (System.currentTimeMillis() - t0) / 1000 + " s: " +
			p.getFunctionManager().getFunctionCount() + " functions.";
	}

	private String analyze(Map<String, String> a) throws Exception {
		return runAnalysis(prog(a));
	}

	private String openProgramCmd(Map<String, String> a) throws Exception {
		String name = req(a, "name");
		DomainFile f = findFile(name);
		if (f == null) {
			throw new UserError("No program named '" + name + "'. Available programs:\n" +
				listPrograms());
		}
		current = openFile(f);
		return "Current program is now " + f.getPathname() + "\n" + programInfo(current);
	}

	private String closeProgramCmd(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String path = p.getDomainFile().getPathname();
		open.remove(path);
		if (current == p) {
			current = null;
		}
		releaseProgram(p);
		return "Closed " + path;
	}

	private String deleteProgram(Map<String, String> a) throws Exception {
		String name = req(a, "name");
		DomainFile f = findFile(name);
		if (f == null) {
			throw new UserError("No program named '" + name + "'.");
		}
		String path = f.getPathname();
		Program p = open.remove(path);
		if (p != null) {
			if (current == p) {
				current = null;
			}
			releaseProgram(p);
		}
		f.delete();
		return "Deleted " + path + " from the Ghidra project.";
	}

	private String programInfo(Program p) {
		StringBuilder sb = new StringBuilder();
		Memory m = p.getMemory();
		sb.append("Program:      ").append(p.getDomainFile().getPathname()).append('\n');
		sb.append("Format:       ").append(p.getExecutableFormat()).append('\n');
		sb.append("Language:     ").append(p.getLanguageID()).append('\n');
		sb.append("Compiler:     ").append(p.getCompilerSpec().getCompilerSpecID()).append('\n');
		sb.append("Image base:   ").append(p.getImageBase()).append('\n');
		Address lo = null, hi = null;
		for (MemoryBlock b : m.getBlocks()) {
			if (!b.getStart().getAddressSpace().isLoadedMemorySpace()) {
				continue; // file-only overlays such as ELF section headers
			}
			lo = lo == null || b.getStart().compareTo(lo) < 0 ? b.getStart() : lo;
			hi = hi == null || b.getEnd().compareTo(hi) > 0 ? b.getEnd() : hi;
		}
		sb.append("Addresses:    ").append(lo).append(" - ").append(hi).append('\n');
		sb.append("Memory:       ").append(m.getBlocks().length).append(" blocks, ")
				.append(m.getSize()).append(" bytes\n");
		sb.append("Functions:    ").append(p.getFunctionManager().getFunctionCount()).append('\n');
		sb.append("Symbols:      ").append(p.getSymbolTable().getNumSymbols()).append('\n');
		sb.append("Analyzed:     ").append(GhidraProgramUtilities.isAnalyzed(p)).append('\n');
		sb.append("Source file:  ").append(p.getExecutablePath()).append('\n');
		sb.append("SHA-256:      ").append(p.getExecutableSHA256());
		return sb.toString();
	}

	// ------------------------------------------------------------------ reading

	private String listFunctions(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String filter = lower(a, "filter");
		Pager pg = new Pager(a);
		for (Function f : p.getFunctionManager().getFunctions(true)) {
			if (matches(f.getName(true), filter)) {
				pg.add(fnLine(f) + "  (" + f.getBody().getNumAddresses() + " bytes)");
			}
		}
		return pg.finish("functions");
	}

	private String functionInfo(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Function f = func(p, req(a, "function"));
		StringBuilder sb = new StringBuilder();
		sb.append("Name:        ").append(f.getName(true)).append('\n');
		sb.append("Entry:       ").append(f.getEntryPoint()).append('\n');
		sb.append("Signature:   ").append(f.getPrototypeString(true, true)).append('\n');
		sb.append("Body:        ").append(f.getBody().getMinAddress()).append(" - ")
				.append(f.getBody().getMaxAddress()).append(" (")
				.append(f.getBody().getNumAddresses()).append(" bytes)\n");
		if (f.isThunk()) {
			sb.append("Thunk to:    ").append(fnLine(f.getThunkedFunction(true))).append('\n');
		}
		if (f.getComment() != null) {
			sb.append("Comment:     ").append(f.getComment()).append('\n');
		}
		sb.append("Parameters:\n");
		for (Parameter prm : f.getParameters()) {
			sb.append("  ").append(prm.getDataType().getDisplayName()).append(' ')
					.append(prm.getName()).append("  @ ").append(prm.getVariableStorage())
					.append('\n');
		}
		sb.append("Locals:\n");
		for (Variable v : f.getLocalVariables()) {
			sb.append("  ").append(v.getDataType().getDisplayName()).append(' ')
					.append(v.getName()).append("  @ ").append(v.getVariableStorage())
					.append('\n');
		}
		sb.append("Called by:\n");
		for (Function c : f.getCallingFunctions(monitor)) {
			sb.append("  ").append(fnLine(c)).append('\n');
		}
		sb.append("Calls:\n");
		for (Function c : f.getCalledFunctions(monitor)) {
			sb.append("  ").append(fnLine(c)).append('\n');
		}
		return sb.toString().trim();
	}

	private String decompile(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Function f = func(p, req(a, "function"));
		if (f.isExternal()) {
			throw new UserError(f.getName() + " is an external (imported) function; there is " +
				"no code to decompile in this program.");
		}
		DecompileResults r = decompileFn(p, f, intArg(a, "timeout", 60, 1, 3600));
		return "// " + f.getName(true) + " @ " + f.getEntryPoint() + "\n" +
			r.getDecompiledFunction().getC().trim();
	}

	private String disassembleCmd(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Listing listing = p.getListing();
		String target = req(a, "address");
		boolean whole = boolArg(a, "whole_function", false);
		int count = intArg(a, "count", 40, 1, 5000);
		InstructionIterator it;
		if (whole) {
			Function f = func(p, target);
			it = listing.getInstructions(f.getBody(), true);
			count = 5000;
		}
		else {
			it = listing.getInstructions(addr(p, target), true);
		}
		StringBuilder sb = new StringBuilder();
		int n = 0;
		while (it.hasNext() && n < count) {
			Instruction ins = it.next();
			Symbol primary = p.getSymbolTable().getPrimarySymbol(ins.getAddress());
			if (primary != null) {
				sb.append(primary.getName(true)).append(":\n");
			}
			StringBuilder hex = new StringBuilder();
			for (byte bt : ins.getBytes()) {
				hex.append(String.format("%02x", bt & 0xff));
			}
			sb.append(String.format("  %s  %-16s %s", ins.getAddress(), hex, ins));
			String c = ins.getComment(CommentType.EOL);
			if (c != null) {
				sb.append("  ; ").append(c.replace('\n', ' '));
			}
			sb.append('\n');
			n++;
		}
		if (n == 0) {
			return "No instructions at " + target +
				". The bytes there are not disassembled; use create_function or read_memory.";
		}
		if (it.hasNext()) {
			sb.append("[stopped after ").append(n).append(" instructions]");
		}
		return sb.toString().trim();
	}

	private String listStrings(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String filter = lower(a, "filter");
		int minLen = intArg(a, "min_length", 1, 1, 100000);
		Pager pg = new Pager(a);
		for (Data d : DefinedStringIterator.forProgram(p)) {
			String s = StringDataInstance.getStringDataInstance(d).getStringValue();
			if (s == null || s.length() < minLen || !matches(s, filter)) {
				continue;
			}
			pg.add(d.getAddress() + "  \"" +
				s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
						.replace("\t", "\\t").replace("\"", "\\\"") +
				"\"");
		}
		return pg.finish("strings");
	}

	private String searchSymbols(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String q = lower(a, "query");
		Pager pg = new Pager(a);
		for (Symbol s : p.getSymbolTable().getAllSymbols(true)) {
			if (matches(s.getName(true), q)) {
				pg.add(s.getAddress() + "  " + s.getName(true) + "  [" + s.getSymbolType() + "]");
			}
		}
		return pg.finish("symbols");
	}

	private String listImports(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String filter = lower(a, "filter");
		Pager pg = new Pager(a);
		for (Symbol s : p.getSymbolTable().getExternalSymbols()) {
			String line = s.getParentNamespace().getName() + "  " + s.getName() + "  [" +
				s.getSymbolType() + "]";
			if (matches(line, filter)) {
				pg.add(line);
			}
		}
		return pg.finish("imports");
	}

	private String listExports(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String filter = lower(a, "filter");
		Pager pg = new Pager(a);
		SymbolTable st = p.getSymbolTable();
		for (Address ad : st.getExternalEntryPointIterator()) {
			Symbol s = st.getPrimarySymbol(ad);
			String name = s == null ? "(unnamed)" : s.getName(true);
			if (matches(name, filter)) {
				pg.add(ad + "  " + name);
			}
		}
		return pg.finish("exports");
	}

	private String listSegments(Map<String, String> a) throws Exception {
		Program p = prog(a);
		StringBuilder sb = new StringBuilder();
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			sb.append(String.format("%-20s %s - %s  %10d bytes  %s%s%s  %s%n", b.getName(),
				b.getStart(), b.getEnd(), b.getSize(), b.isRead() ? "r" : "-",
				b.isWrite() ? "w" : "-", b.isExecute() ? "x" : "-",
				b.isInitialized() ? "initialized" : "uninitialized"));
		}
		return sb.length() == 0 ? "No memory blocks." : sb.toString().trim();
	}

	private String where(Program p, Address ad) {
		Function f = p.getFunctionManager().getFunctionContaining(ad);
		return f == null ? "" : "  in " + f.getName(true);
	}

	private String xrefsTo(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Address target = addr(p, req(a, "address"));
		Pager pg = new Pager(a);
		Set<String> seen = new java.util.HashSet<>();
		List<Address> hops = new ArrayList<>();

		// A function may be reached through thunks (PLT stubs, import jump stubs): calls to
		// those stubs are calls to the function, so they are followed as well.
		Function fn = p.getFunctionManager().getFunctionAt(target);
		if (fn == null) {
			Symbol sym = p.getSymbolTable().getPrimarySymbol(target);
			if (sym != null && sym.getObject() instanceof Function) {
				fn = (Function) sym.getObject();
			}
		}
		if (fn != null) {
			Address[] thunks = fn.getFunctionThunkAddresses(true);
			if (thunks != null) {
				for (Address t : thunks) {
					hops.add(t);
				}
			}
		}

		ReferenceIterator it = p.getReferenceManager().getReferencesTo(target);
		while (it.hasNext()) {
			Reference r = it.next();
			Address from = r.getFromAddress();
			if (seen.add(from.toString())) {
				pg.add(from + "  " + r.getReferenceType() + where(p, from));
			}
			// An imported function is also reached through its import-table slot.
			if (target.isExternalAddress() && from.isMemoryAddress() && !hops.contains(from)) {
				hops.add(from);
			}
		}
		for (Address hop : hops) {
			ReferenceIterator via = p.getReferenceManager().getReferencesTo(hop);
			while (via.hasNext()) {
				Reference v = via.next();
				Address from = v.getFromAddress();
				Function holder = p.getFunctionManager().getFunctionContaining(from);
				if (holder == null || holder.isThunk() || hops.contains(from) ||
					!seen.add(from.toString())) {
					continue; // table entries, the stub itself, or already listed
				}
				pg.add("  " + from + "  " + v.getReferenceType() + where(p, from) + "  (via " +
					hop + ")");
			}
		}
		return pg.finish("references to " + target);
	}

	private String xrefsFrom(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String target = req(a, "address");
		Pager pg = new Pager(a);
		AddressSet set;
		Function f = null;
		if (boolArg(a, "whole_function", false)) {
			f = func(p, target);
			set = new AddressSet(f.getBody());
		}
		else {
			Address ad = addr(p, target);
			CodeUnit cu = p.getListing().getCodeUnitContaining(ad);
			set = cu == null ? new AddressSet(ad) : new AddressSet(cu.getMinAddress(),
				cu.getMaxAddress());
		}
		for (Address from : p.getReferenceManager().getReferenceSourceIterator(set, true)) {
			for (Reference r : p.getReferenceManager().getReferencesFrom(from)) {
				Symbol s = p.getSymbolTable().getPrimarySymbol(r.getToAddress());
				pg.add(from + " -> " + r.getToAddress() + "  " + r.getReferenceType() +
					(s == null ? "" : "  " + s.getName(true)));
			}
		}
		return pg.finish("references from " + (f != null ? f.getName() : target));
	}

	private String readMemory(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Address start = addr(p, req(a, "address"));
		int len = intArg(a, "length", 64, 1, 65536);
		byte[] buf = new byte[len];
		int got;
		try {
			got = p.getMemory().getBytes(start, buf);
		}
		catch (Exception e) {
			throw new UserError("Cannot read memory at " + start + ": " + e.getMessage() +
				". Use list_segments to see the mapped ranges.");
		}
		StringBuilder sb = new StringBuilder();
		for (int off = 0; off < got; off += 16) {
			StringBuilder hex = new StringBuilder();
			StringBuilder asc = new StringBuilder();
			for (int i = off; i < off + 16; i++) {
				if (i < got) {
					int v = buf[i] & 0xff;
					hex.append(String.format("%02x ", v));
					asc.append(v >= 0x20 && v < 0x7f ? (char) v : '.');
				}
				else {
					hex.append("   ");
				}
			}
			sb.append(start.add(off)).append("  ").append(hex).append(' ').append(asc)
					.append('\n');
		}
		return sb.toString().trim();
	}

	private String searchBytes(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String[] toks = req(a, "pattern").trim().replace(",", " ").split("\\s+");
		List<String> parts = new ArrayList<>();
		for (String t : toks) {
			String x = t.startsWith("0x") || t.startsWith("0X") ? t.substring(2) : t;
			if (x.length() % 2 != 0) {
				throw new UserError("Bad pattern token '" + t + "': use hex byte pairs, ?? for " +
					"a wildcard byte, e.g. \"7f 45 4c 46\" or \"e8 ?? ?? ?? ?? 85 c0\".");
			}
			for (int i = 0; i < x.length(); i += 2) {
				parts.add(x.substring(i, i + 2));
			}
		}
		byte[] bytes = new byte[parts.size()];
		byte[] mask = new byte[parts.size()];
		for (int i = 0; i < bytes.length; i++) {
			String s = parts.get(i);
			if (s.equals("??") || s.equals("..")) {
				mask[i] = 0;
			}
			else {
				try {
					bytes[i] = (byte) Integer.parseInt(s, 16);
				}
				catch (NumberFormatException e) {
					throw new UserError("Bad hex byte '" + s + "' in pattern.");
				}
				mask[i] = (byte) 0xff;
			}
		}
		int limit = intArg(a, "limit", 50, 1, 5000);
		Memory m = p.getMemory();
		StringBuilder sb = new StringBuilder();
		Address at = p.getMinAddress();
		int n = 0;
		while (at != null && n < limit) {
			Address hit = m.findBytes(at, bytes, mask, true, monitor);
			if (hit == null) {
				break;
			}
			sb.append(hit).append(where(p, hit)).append('\n');
			n++;
			try {
				at = hit.addNoWrap(1);
			}
			catch (Exception e) {
				break;
			}
		}
		if (n == 0) {
			return "Pattern not found.";
		}
		sb.append("[").append(n).append(n == limit ? " matches (limit reached)]" : " matches]");
		return sb.toString();
	}

	// ------------------------------------------------------------------ modifying

	private String renameFunction(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Function f = func(p, req(a, "function"));
		String name = req(a, "new_name");
		String old = f.getName();
		return modify(p, "rename function", () -> {
			f.setName(name, SourceType.USER_DEFINED);
			return "Renamed function " + old + " -> " + name + " @ " + f.getEntryPoint();
		});
	}

	private String renameVariable(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Function f = func(p, req(a, "function"));
		String oldName = req(a, "old_name");
		String newName = req(a, "new_name");
		for (Variable v : f.getAllVariables()) {
			if (v.getName().equals(oldName)) {
				return modify(p, "rename variable", () -> {
					v.setName(newName, SourceType.USER_DEFINED);
					return "Renamed " + oldName + " -> " + newName + " in " + f.getName();
				});
			}
		}
		// Not a stored variable: look for it among the decompiler's variables.
		HighFunction hf = decompileFn(p, f, 60).getHighFunction();
		Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
		StringBuilder names = new StringBuilder();
		while (it.hasNext()) {
			HighSymbol sym = it.next();
			if (sym.getName().equals(oldName)) {
				return modify(p, "rename variable", () -> {
					if (sym.isParameter()) {
						HighFunctionDBUtil.commitParamsToDatabase(hf, true,
							ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS);
						for (Parameter prm : f.getParameters()) {
							if (prm.getOrdinal() == sym.getCategoryIndex()) {
								prm.setName(newName, SourceType.USER_DEFINED);
							}
						}
					}
					else {
						HighFunctionDBUtil.updateDBVariable(sym, newName, null,
							SourceType.USER_DEFINED);
					}
					return "Renamed " + oldName + " -> " + newName + " in " + f.getName();
				});
			}
			names.append(names.length() == 0 ? "" : ", ").append(sym.getName());
		}
		throw new UserError("No variable '" + oldName + "' in " + f.getName() +
			". Variables: " + names);
	}

	private String setSignature(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Function f = func(p, req(a, "function"));
		String text = req(a, "signature");
		FunctionDefinitionDataType def;
		try {
			def = new FunctionSignatureParser(p.getDataTypeManager(), null)
					.parse(f.getSignature(), text);
		}
		catch (Exception e) {
			throw new UserError("Cannot parse signature '" + text + "': " + e.getMessage() +
				". Use C syntax such as \"int check_key(char *key, int len)\".");
		}
		return modify(p, "set signature", () -> {
			// Without a concrete calling convention the decompiler cannot place the parameters.
			if (Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(f.getCallingConventionName())) {
				f.setCallingConvention(
					p.getCompilerSpec().getDefaultCallingConvention().getName());
			}
			ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), def,
				SourceType.USER_DEFINED, true, true);
			if (!cmd.applyTo(p, monitor)) {
				throw new UserError("Could not apply signature: " + cmd.getStatusMsg());
			}
			return "Signature is now: " + f.getPrototypeString(true, true);
		});
	}

	private String createLabel(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Address ad = addr(p, req(a, "address"));
		String name = req(a, "name");
		return modify(p, "create label", () -> {
			Symbol s = p.getSymbolTable().createLabel(ad, name, SourceType.USER_DEFINED);
			s.setPrimary();
			return "Label " + name + " set at " + ad;
		});
	}

	private String setComment(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Address ad = addr(p, req(a, "address"));
		String text = a.getOrDefault("comment", "");
		String kind = a.getOrDefault("type", "eol").toLowerCase(Locale.ROOT);
		CommentType type;
		switch (kind) {
			case "eol":
				type = CommentType.EOL;
				break;
			case "pre":
			case "decompiler":
				type = CommentType.PRE;
				break;
			case "post":
				type = CommentType.POST;
				break;
			case "plate":
				type = CommentType.PLATE;
				break;
			case "repeatable":
				type = CommentType.REPEATABLE;
				break;
			default:
				throw new UserError("Unknown comment type '" + kind +
					"'. Use eol, pre, post, plate or repeatable.");
		}
		return modify(p, "set comment", () -> {
			p.getListing().setComment(ad, type, text.isEmpty() ? null : text);
			return (text.isEmpty() ? "Cleared " : "Set ") + kind + " comment at " + ad;
		});
	}

	private String createFunctionCmd(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Address ad = addr(p, req(a, "address"));
		String name = a.get("name");
		return modify(p, "create function", () -> {
			if (p.getListing().getInstructionAt(ad) == null) {
				new DisassembleCommand(ad, null, true).applyTo(p, monitor);
			}
			Function f = p.getFunctionManager().getFunctionAt(ad);
			if (f == null) {
				CreateFunctionCmd cmd = new CreateFunctionCmd(ad);
				if (!cmd.applyTo(p, monitor)) {
					throw new UserError("Could not create a function at " + ad + ": " +
						cmd.getStatusMsg());
				}
				f = p.getFunctionManager().getFunctionAt(ad);
			}
			if (name != null && !name.isEmpty()) {
				f.setName(name, SourceType.USER_DEFINED);
			}
			AutoAnalysisManager.getAnalysisManager(p).startAnalysis(monitor);
			return "Function " + fnLine(f) + " (" + f.getBody().getNumAddresses() + " bytes)";
		});
	}

	// Fixed-width integer names are not part of C itself; make them available to declarations.
	private static final String STDINT =
		"typedef unsigned char uint8_t; typedef signed char int8_t; " +
			"typedef unsigned short uint16_t; typedef short int16_t; " +
			"typedef unsigned int uint32_t; typedef int int32_t; " +
			"typedef unsigned long long uint64_t; typedef long long int64_t;\n";

	private String defineType(Map<String, String> a) throws Exception {
		Program p = prog(a);
		String decl = req(a, "declaration").trim();
		if (!decl.endsWith(";")) {
			decl += ";";
		}
		DataTypeManager dtm = p.getDataTypeManager();
		DataType parsed;
		try {
			parsed = new CParser(dtm, false, null).parse(STDINT + decl);
		}
		catch (Throwable t) {
			String msg = t.getMessage() == null ? t.toString() : t.getMessage();
			throw new UserError("Cannot parse the declaration: " + msg.split("\n")[0] +
				"\nUse plain C, e.g. \"struct Point { int x; int y; };\" or " +
				"\"typedef struct { char name[24]; uint16_t count; } Item;\".");
		}
		if (parsed == null) {
			throw new UserError("The declaration defines no type. Use plain C, e.g. " +
				"\"struct Point { int x; int y; };\".");
		}
		final DataType toStore = parsed;
		return modify(p, "define type", () -> {
			DataType dt = dtm.addDataType(toStore, DataTypeConflictHandler.REPLACE_HANDLER);
			StringBuilder sb = new StringBuilder();
			sb.append("Defined ").append(dt.getName()).append(" (").append(dt.getLength())
					.append(" bytes)");
			DataType base = dt instanceof TypeDef ? ((TypeDef) dt).getBaseDataType() : dt;
			if (base instanceof Composite) {
				sb.append("\noffset  size  field");
				for (DataTypeComponent c : ((Composite) base).getDefinedComponents()) {
					sb.append(String.format("%n0x%02x    %4d  %s %s", c.getOffset(), c.getLength(),
						c.getDataType().getDisplayName(),
						c.getFieldName() == null ? "(unnamed)" : c.getFieldName()));
				}
			}
			sb.append("\nUse it in set_function_signature, e.g. \"int f(").append(dt.getName())
					.append(" *p)\".");
			return sb.toString();
		});
	}

	private DataType parseType(Program p, String text) {
		try {
			DataTypeManager dtm = p.getDataTypeManager();
			return new DataTypeParser(dtm, dtm, null, DataTypeParser.AllowedDataTypes.ALL)
					.parse(text.trim());
		}
		catch (Exception e) {
			throw new UserError("Unknown type '" + text + "'. Use a C base type (char, int, " +
				"unsigned int, ...), a Ghidra name (uchar, ushort, uint, ulong) or a type created " +
				"with define_type, optionally followed by * or [n], e.g. \"Record[64]\".");
		}
	}

	private String setVariableType(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Function f = func(p, req(a, "function"));
		String name = req(a, "variable");
		DataType dt = parseType(p, req(a, "type"));
		String done = name + " in " + f.getName() + " is now " + dt.getDisplayName() + " (" +
			dt.getLength() + " bytes). Decompile again to see the effect.";
		for (Variable v : f.getAllVariables()) {
			if (v.getName().equals(name)) {
				return modify(p, "set variable type", () -> {
					v.setDataType(dt, false, true, SourceType.USER_DEFINED);
					return done;
				});
			}
		}
		HighFunction hf = decompileFn(p, f, 60).getHighFunction();
		Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
		StringBuilder names = new StringBuilder();
		while (it.hasNext()) {
			HighSymbol sym = it.next();
			if (sym.getName().equals(name)) {
				return modify(p, "set variable type", () -> {
					if (sym.isParameter()) {
						HighFunctionDBUtil.commitParamsToDatabase(hf, true,
							ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS);
						for (Parameter prm : f.getParameters()) {
							if (prm.getOrdinal() == sym.getCategoryIndex()) {
								prm.setDataType(dt, false, true, SourceType.USER_DEFINED);
							}
						}
					}
					else {
						HighFunctionDBUtil.updateDBVariable(sym, null, dt, SourceType.USER_DEFINED);
					}
					return done;
				});
			}
			names.append(names.length() == 0 ? "" : ", ").append(sym.getName());
		}
		throw new UserError("No variable '" + name + "' in " + f.getName() + ". Variables: " +
			names);
	}

	private String setDataType(Map<String, String> a) throws Exception {
		Program p = prog(a);
		Address ad = addr(p, req(a, "address"));
		DataType dt = parseType(p, req(a, "type"));
		return modify(p, "set data type", () -> {
			try {
				DataUtilities.createData(p, ad, dt, -1,
					DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
			catch (Exception e) {
				throw new UserError("Cannot apply " + dt.getDisplayName() + " at " + ad + ": " +
					e.getMessage());
			}
			return "Applied " + dt.getDisplayName() + " at " + ad + " (" + dt.getLength() +
				" bytes).";
		});
	}
}
