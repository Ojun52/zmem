const std = @import("std");
const Io = std.Io;

const zmem = @import("zmem");
const clap = @import("clap");

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
        var path_buf: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/proc/{}/maps", .{pid});
        const file = try Io.Dir.openFileAbsolute(init.io, path, .{ .mode = .read_only });
        defer file.close(init.io);

        var file_buf: [4096]u8 = undefined;
        var file_reader = file.reader(init.io, file_buf[0..]);
        var reader = &file_reader.interface;

        var lst = try std.ArrayListAligned(u8, null).initCapacity(init.gpa, 4096);
        defer lst.deinit(init.gpa);

        var temp_buf: [4096]u8 = undefined;
        while (true) {
            const n = try reader.readSliceShort(&temp_buf);
            if (n == 0) break;

            try lst.appendSlice(init.gpa, &temp_buf);
        }

        std.debug.print("{s}", .{lst.items});
    }
}
