const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});
    const allocator = std.heap.page_allocator;

    const lib = b.addStaticLibrary(.{
        .name = "rnd_compress",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "rnd_compress",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Run NASM to generate the .o file
    // Determine the appropriate ASM file and NASM format based on the OS
    const asm_file = switch (target.result.os.tag) {
        .windows => "src\\rnd_win.asm",
        .linux => "src/rnd_lin.asm",
        else => {
            std.log.err("Unsupported operating system: {}", .{target.result.os.tag});
            return;
        },
    };

    const nasm_format = switch (target.result.os.tag) {
        .windows => "win64",
        .linux => "elf64",
        else => {
            std.log.err("Unsupported NASM format for OS: {}", .{target.result.os.tag});
            return;
        },
    };

    // Ensure the output directory exists
    const asm_output_dir = b.cache_root.join(allocator, &.{"asm_files"}) catch |e| {
        std.log.err("Could not join dir: {}\n", .{e});
        return;
    };

    const root_dir = std.fs.openDirAbsolute(b.build_root.path.?, .{}) catch |e| {
        std.log.err("Could not open the dir: {}\n", .{e});
        return;
    };
    root_dir.makeDir(asm_output_dir) catch |e| {
        if (e != error.PathAlreadyExists) {
            std.log.err("Could not make dir: {}\n", .{e});

            return;
        }
    };

    // Assemble the ASM file
    const asm_output_path = std.mem.concat(allocator, u8, &[_][]const u8{ asm_output_dir, "/rnd_asm_module.o" }) catch |e|
        {
        std.log.err("Could not concat paths: {}\n", .{e});
        return;
    };
    std.log.info("Building {s} for {s} into {s}\n", .{ asm_file, nasm_format, asm_output_path });
    const nasm_result = std.process.Child.run(.{
        .argv = &[_][]const u8{
            "nasm",
            "-f",
            nasm_format,
            asm_file,
            "-o",
            asm_output_path,
        },
        .allocator = std.heap.page_allocator,
    }) catch |e| {
        std.debug.print("Asm build failed -> {}\n", .{e});
        return;
    };

    std.debug.print("nasm output: {s}\n", .{nasm_result.stderr});

    // Add object file to the executable
    exe.addObjectFile(b.path(".zig-cache\\asm_files\\rnd_asm_module.o"));
    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
