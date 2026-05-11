const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;

const zmem = @import("zmem");
const clap = @import("clap");

fn get_memory_map(io: Io, pid: usize, allocator: std.mem.Allocator, buf: *std.ArrayListAligned(u8, null)) !void {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/proc/{}/maps", .{pid});
    const file = try Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only });
    defer file.close(io);

    var file_buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, file_buf[0..]);
    var reader = &file_reader.interface;

    var temp_buf: [4096]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&temp_buf);
        if (n == 0) break;

        try buf.appendSlice(allocator, temp_buf[0..n]);
    }
}

fn get_process_memory(pid: linux.pid_t, local_iov: []const std.posix.iovec, addr: usize, len: usize) isize {
    const remote = [1]std.posix.iovec_const{.{
        .base = @ptrFromInt(addr),
        .len = len,
    }};
    return @bitCast(linux.process_vm_readv(
        pid,
        local_iov,
        &remote,
        0,
    ));
}

// False means no error.
fn analyze_readv_error(nread: isize, addr: usize, len: usize) bool {
    if (nread >= 0) return false; // No error

    const err = std.posix.errno(@bitCast(nread));
    const err_name = @tagName(err);

    std.debug.print("\n[!] Error: Failed to read memory at 0x{x:0>16}-0x{x:0>16}\n", .{ addr, addr + len });
    std.debug.print("    Detail: {s} (Code: {d})\n", .{ err_name, @intFromEnum(err) });

    switch (err) {
        .PERM => std.debug.print("    Hint: Permission denied. Try 'sudo' or check ptrace_scope.\n", .{}),
        .ACCES => std.debug.print("    Hint: Access denied. Maybe another debugger is attached?\n", .{}),
        .FAULT => std.debug.print("    Hint: Bad address or no read permission (check maps).\n", .{}),
        .SRCH => std.debug.print("    Hint: Process not found. Check if PID is still alive.\n", .{}),
        else => std.debug.print("    Hint: Unknown system error. See 'man 2 process_vm_readv'.\n", .{}),
    }

    return true;
}

pub fn main(init: std.process.Init) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\-p, --pid <u32>        Pid of the process you want to investigate.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, init.minimal.args, .{
        .diagnostic = &diag,
        .allocator = init.gpa,
    }) catch |err| {
        try diag.reportToFile(init.io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0)
        return clap.helpToFile(init.io, .stderr(), clap.Help, &params, .{});

    if (res.args.pid) |pid| {
        var mmap_buf = try std.ArrayListAligned(u8, null).initCapacity(init.gpa, 4096);
        defer mmap_buf.deinit(init.gpa);

        try get_memory_map(init.io, pid, init.gpa, &mmap_buf);
        std.debug.print("{s}", .{mmap_buf.items});

        var mem_buf: [64]u8 = undefined;
        const local_iov = [1]std.posix.iovec{.{ .base = &mem_buf, .len = mem_buf.len }};

        const addr = 0x7ffdadb98620;
        const read_n: isize = get_process_memory(@bitCast(pid), &local_iov, addr, 64);

        if (!analyze_readv_error(read_n, addr, mem_buf.len)) {
            std.debug.print("Read {d} bytes from 0x{x}.\n", .{ read_n, addr });
            std.debug.print("{s}\n", .{std.fmt.bytesToHex(&mem_buf, std.fmt.Case.lower)});
        }
    }
}
