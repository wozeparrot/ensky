const std = @import("std");
const net = std.net;
const Thread = std.Thread;

pub fn main() !void {
    // spawn gossip thread
    const gossip_thread = try Thread.spawn(.{}, gossip, .{});
    defer gossip_thread.join();

    while (true) {}
}

fn gossip() !void {
    while (true) {}
}
