const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const crypto = std.crypto;
const json = std.json;
const log = std.log;
const posix = std.posix;
const time = std.time;

const network = @import("deps/zig-network/network.zig");

// --- CONFIGURATION ---
const GOSSIP_SLEEP_SECS = 30;
const CONFIG_SLEEP_SECS = 30;
const PEER_TIMEOUT_SECS = 200;

// --- CODE ---
const State = struct {
    interface: []const u8,

    gossip_address: []const u8,
    gossip_port: u16,
    gossip_secret_path: []const u8,
    gossip_key: [crypto.hash.Blake3.digest_length]u8 = undefined,

    our_pubkey: []const u8 = "",
    our_port: u16 = 5553,
    peers: []Peer,
};

const Peer = struct {
    pubkey: []const u8,
    endpoints: [][]const u8,
    allowed_ips: [][]const u8,

    last_handshake: u64 = 0,
    cycles_survived: usize = 0,
    i: usize = 0,
    current_endpoint: []const u8 = "",
};

pub fn main() !void {
    var alloc_buf: [8 * 1024 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
    const alloc = fba.threadSafeAllocator();

    // args
    var args = std.process.args();
    const prog_name = args.next().?;

    // load config
    const config_path = args.next();
    if (config_path == null) {
        log.err("usage: {s} <config-path>", .{prog_name});
        posix.exit(1);
    }
    const config_file = try std.fs.cwd().openFile(config_path.?, .{});
    defer config_file.close();
    var buf: [2 * 1024 * 1024]u8 = undefined;
    const len = try config_file.readAll(buf[0..]);
    var state = try json.parseFromSliceLeaky(State, alloc, buf[0..len], .{});
    var state_lock = std.Thread.RwLock{};

    // load gossip key
    const gossip_secret_path = state.gossip_secret_path;
    const gossip_secret_file = try std.fs.cwd().openFile(gossip_secret_path, .{});
    defer gossip_secret_file.close();
    const gossip_secret = try gossip_secret_file.readToEndAlloc(alloc, std.math.maxInt(usize));
    crypto.hash.Blake3.hash(gossip_secret, &state.gossip_key, .{});
    alloc.free(gossip_secret);

    // initialize zig-network
    try network.init();
    defer network.deinit();

    log.info("ensky starting!", .{});

    // spawn gossip tx thread
    const gossip_tx_thread = try Thread.spawn(.{}, gossipTx, .{ alloc, &state, &state_lock });
    defer gossip_tx_thread.join();

    // spawn gossip rx thread
    const gossip_rx_thread = try Thread.spawn(.{}, gossipRx, .{ alloc, &state, &state_lock });
    defer gossip_rx_thread.join();

    const slog = log.scoped(.config);
    while (true) {
        slog.debug("configuring", .{});

        slog.debug("dumping wireguard", .{});
        dumpWireguard(alloc, &state, &state_lock) catch {
            slog.err("failed to dump wireguard!", .{});
            posix.exit(1);
        };
        slog.debug("we are on port: {}", .{state.our_port});

        state_lock.lockShared();
        for (state.peers) |*peer| {
            if (std.mem.eql(u8, peer.pubkey, state.our_pubkey)) continue;
            slog.debug("configuring peer: {s}, last_handshake: {}", .{ peer.pubkey, peer.last_handshake });
            setWgAllowedIPs(alloc, state.interface, peer.pubkey, peer.allowed_ips) catch {
                slog.warn("failed to set allowed ips!", .{});
                posix.exit(1);
            };

            // see if this peer has timed out
            const now = std.time.timestamp();
            if (now < peer.last_handshake + PEER_TIMEOUT_SECS) {
                peer.cycles_survived += 1;

                // if the peer has survived enough cycles we can assume that its a good endpoint
                if (peer.cycles_survived == (PEER_TIMEOUT_SECS / CONFIG_SLEEP_SECS) + 1) {
                    slog.info("peer has survived enough cycles, assuming good endpoint", .{});
                    setWgKeepAlive(alloc, state.interface, peer.pubkey, 25) catch {
                        slog.warn("failed to set keepalive!", .{});
                        posix.exit(1);
                    };
                }

                continue;
            } else {
                slog.warn("peer has timed out", .{});
                setWgKeepAlive(alloc, state.interface, peer.pubkey, 5) catch {
                    slog.warn("failed to set keepalive!", .{});
                    posix.exit(1);
                };
                peer.cycles_survived = 0;
            }

            if (peer.endpoints.len == 0) {
                slog.warn("peer has no known endpoints", .{});
                continue;
            }

            // pick the ith endpoint
            const endpoint = peer.endpoints[peer.i];
            slog.info("testing endpoint: {s}", .{endpoint});
            setWgEndpoint(alloc, state.interface, peer.pubkey, endpoint) catch {
                slog.warn("failed to set endpoint!", .{});
                posix.exit(1);
            };
            peer.current_endpoint = endpoint;
            peer.i = (peer.i + 1) % peer.endpoints.len;
        }
        state_lock.unlockShared();

        time.sleep(CONFIG_SLEEP_SECS * time.ns_per_s);
    }
}

fn setWgEndpoint(alloc: Allocator, interface: []const u8, pubkey: []const u8, endpoint: []const u8) !void {
    const slog = log.scoped(.set_wg_endpoint);

    const res = try std.ChildProcess.run(.{
        .allocator = alloc,
        .argv = &[_][]const u8{ "wg", "set", interface, "peer", pubkey, "endpoint", endpoint },
        .max_output_bytes = 2 * 1024 * 1024,
    });
    defer {
        alloc.free(res.stderr);
        alloc.free(res.stdout);
    }

    if (res.term.Exited != 0) {
        slog.err("failed to set endpoint: {s}", .{res.stderr});
        return error.UnexpectedError;
    }
}

fn setWgAllowedIPs(alloc: Allocator, interface: []const u8, pubkey: []const u8, allowed_ips: []const []const u8) !void {
    const slog = log.scoped(.set_wg_allowed_ips);

    const allowed_ips_str = try std.mem.join(alloc, ",", allowed_ips);
    defer alloc.free(allowed_ips_str);

    const res = try std.ChildProcess.run(.{
        .allocator = alloc,
        .argv = &[_][]const u8{ "wg", "set", interface, "peer", pubkey, "allowed-ips", allowed_ips_str },
        .max_output_bytes = 2 * 1024 * 1024,
    });
    defer {
        alloc.free(res.stderr);
        alloc.free(res.stdout);
    }

    if (res.term.Exited != 0) {
        slog.err("failed to set allowed ips: {s}", .{res.stderr});
        return error.UnexpectedError;
    }
}

fn setWgKeepAlive(alloc: Allocator, interface: []const u8, pubkey: []const u8, keep_alive: usize) !void {
    const slog = log.scoped(.set_wg_keepalive);

    const keep_alive_str = try std.fmt.allocPrint(alloc, "{}", .{keep_alive});
    defer alloc.free(keep_alive_str);

    const res = try std.ChildProcess.run(.{
        .allocator = alloc,
        .argv = &[_][]const u8{ "wg", "set", interface, "peer", pubkey, "persistent-keepalive", keep_alive_str },
        .max_output_bytes = 2 * 1024 * 1024,
    });
    defer {
        alloc.free(res.stderr);
        alloc.free(res.stdout);
    }

    if (res.term.Exited != 0) {
        slog.err("failed to set persistent keepalive: {s}", .{res.stderr});
        return error.UnexpectedError;
    }
}

fn dumpWireguard(alloc: Allocator, state: *State, state_lock: *std.Thread.RwLock) !void {
    const slog = log.scoped(.dump_wireguard);

    const res = try std.ChildProcess.run(.{
        .allocator = alloc,
        .argv = &[_][]const u8{ "wg", "show", state.interface, "dump" },
        .max_output_bytes = 2 * 1024 * 1024,
    });
    defer alloc.free(res.stderr);

    if (res.term.Exited != 0) {
        slog.err("{s}", .{res.stderr});
        return error.UnexpectedError;
    }

    state_lock.lock();
    defer state_lock.unlock();

    var lines_iter = std.mem.split(u8, res.stdout, "\n");
    // try to parse ourself first
    const our_line = lines_iter.next();
    if (our_line) |line| {
        var tab_iter = std.mem.split(u8, line, "\t");

        _ = tab_iter.next();
        state.our_pubkey = tab_iter.next().?;
        state.our_port = try std.fmt.parseInt(u16, tab_iter.next().?, 10);
    } else {
        slog.err("empty wg dump! did you choose the right interface?", .{});
        return error.UnexpectedError;
    }

    var found_peers = std.StringHashMap(void).init(alloc);
    defer found_peers.deinit();

    while (lines_iter.next()) |line| {
        if (line.len == 0) continue;

        var tab_iter = std.mem.split(u8, line, "\t");

        const pubkey = tab_iter.next().?;
        slog.debug("found pubkey: {s}", .{pubkey});
        if (std.mem.eql(u8, pubkey, state.our_pubkey)) continue;

        // see if we have a peer with this pubkey
        var peer: ?*Peer = null;
        for (state.peers) |*p| {
            if (std.mem.eql(u8, p.pubkey, pubkey)) {
                peer = p;
                break;
            }
        }
        if (peer == null) continue;
        slog.debug("found peer: {s}", .{pubkey});
        try found_peers.put(pubkey, {});

        // skip the preshared key
        _ = tab_iter.next();

        const endpoint = tab_iter.next().?;
        if (!std.mem.eql(u8, peer.?.current_endpoint, endpoint)) {
            slog.info("setting current endpoint to {s} for peer: {s}", .{ endpoint, pubkey });
            peer.?.current_endpoint = endpoint;
        }

        // skip allowed ips
        _ = tab_iter.next();

        peer.?.last_handshake = std.fmt.parseInt(u64, tab_iter.next().?, 10) catch 0;
    }

    for (state.peers) |*peer| {
        if (peer.last_handshake == 0) continue;
        if (found_peers.get(peer.pubkey) == null) {
            slog.info("peer {s} has disappeared", .{peer.pubkey});
            peer.last_handshake = 0;
            peer.current_endpoint = "";
        }
    }
}

fn gossipTx(alloc: Allocator, state: *State, state_lock: *std.Thread.RwLock) !void {
    const slog = log.scoped(.gossip_tx);

    // create udp socket
    var sock = try network.Socket.create(.ipv4, .udp);
    defer sock.close();

    while (true) {
        slog.debug("gossiping", .{});

        const now = time.timestamp();

        state_lock.lock();
        for (state.peers) |*peer| {
            if (std.mem.eql(u8, peer.pubkey, state.our_pubkey)) continue;
            if (peer.current_endpoint.len == 0) continue;
            if (peer.last_handshake == 0) continue;
            if (!(now < peer.last_handshake + PEER_TIMEOUT_SECS)) continue;

            // send a gossip message to all the peers that we know
            for (state.peers) |p| {
                if (std.mem.eql(u8, p.pubkey, peer.pubkey)) continue;
                if (std.mem.eql(u8, p.pubkey, state.our_pubkey)) continue;
                if (p.current_endpoint.len == 0) continue;
                if (p.last_handshake == 0) continue;
                if (!(now < p.last_handshake + PEER_TIMEOUT_SECS)) continue;

                slog.debug("sending gossip that {s} is at {s} to {s}", .{ peer.pubkey, peer.current_endpoint, p.current_endpoint });

                // encrypt with xchacha20poly1305
                var buf: [2 * 1024 * 1024]u8 = undefined;
                const plaintext = try std.fmt.bufPrint(&buf, "{s}|%|{s}", .{ peer.pubkey, peer.current_endpoint });
                slog.debug("plaintext: {s}, len: {}", .{ plaintext, plaintext.len });
                var ciphertext: [4 * 1024]u8 = undefined;
                var tag: [crypto.aead.chacha_poly.XChaCha20Poly1305.tag_length]u8 = undefined;
                var nonce: [crypto.aead.chacha_poly.XChaCha20Poly1305.nonce_length]u8 = undefined;
                crypto.random.bytes(&nonce);
                crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(ciphertext[0..plaintext.len], &tag, plaintext, "", nonce, state.gossip_key);

                const msg = try std.mem.join(alloc, "", &[_][]const u8{
                    nonce[0..],
                    ciphertext[0..plaintext.len],
                    tag[0..],
                });
                defer alloc.free(msg);

                var colon_iter = std.mem.split(u8, p.current_endpoint, ":");
                _ = try sock.sendTo(network.EndPoint{
                    .address = .{ .ipv4 = try network.Address.IPv4.parse(colon_iter.next().?) },
                    .port = state.gossip_port,
                }, msg);
            }
        }
        state_lock.unlock();

        time.sleep(GOSSIP_SLEEP_SECS * time.ns_per_s);
    }
}

fn gossipRx(alloc: Allocator, state: *State, state_lock: *std.Thread.RwLock) !void {
    const slog = log.scoped(.gossip_rx);

    // create udp socket
    var sock = try network.Socket.create(.ipv4, .udp);
    defer sock.close();
    try sock.enablePortReuse(true);
    try sock.bind(network.EndPoint{
        .address = .{ .ipv4 = try network.Address.IPv4.parse(state.gossip_address) },
        .port = state.gossip_port,
    });
    slog.info("binding to: {s}:{}", .{ state.gossip_address, state.gossip_port });

    var buf: [2 * 1024 * 1024]u8 = undefined;
    while (true) {
        const recv = try sock.receiveFrom(&buf);
        const msg = buf[0..recv.numberOfBytes];
        slog.debug("received gossip: len {}", .{msg.len});

        // decrypt with xchacha20poly1305
        if (msg.len < crypto.aead.chacha_poly.XChaCha20Poly1305.nonce_length) {
            slog.warn("received invalid gossip message: too short", .{});
            continue;
        }

        var nonce: [crypto.aead.chacha_poly.XChaCha20Poly1305.nonce_length]u8 = undefined;
        @memcpy(&nonce, msg[0..crypto.aead.chacha_poly.XChaCha20Poly1305.nonce_length]);
        const ciphertext = msg[crypto.aead.chacha_poly.XChaCha20Poly1305.nonce_length .. msg.len - crypto.aead.chacha_poly.XChaCha20Poly1305.tag_length];
        var tag: [crypto.aead.chacha_poly.XChaCha20Poly1305.tag_length]u8 = undefined;
        @memcpy(&tag, msg[msg.len - crypto.aead.chacha_poly.XChaCha20Poly1305.tag_length ..]);

        const plaintext = try alloc.alloc(u8, ciphertext.len);
        crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(plaintext, ciphertext, tag, "", nonce, state.gossip_key) catch {
            slog.warn("received invalid gossip message: decryption failed", .{});
            continue;
        };

        var split_iter = std.mem.split(u8, plaintext, "|%|");
        const pubkey = split_iter.next().?;
        const endpoint = split_iter.next().?;
        slog.debug("{s} is at {s}", .{ pubkey, endpoint });

        state_lock.lock();
        var peer: ?*Peer = null;
        for (state.peers) |*p| {
            if (std.mem.eql(u8, p.pubkey, pubkey)) {
                peer = p;
                break;
            }
        }
        if (peer == null) continue;

        // add the endpoint if we don't have it
        var found = false;
        for (peer.?.endpoints) |e| {
            if (std.mem.eql(u8, e, endpoint)) {
                found = true;
                break;
            }
        }
        if (!found) {
            slog.info("adding endpoint {s} to {s}", .{ endpoint, pubkey });
            peer.?.endpoints = try alloc.realloc(peer.?.endpoints, peer.?.endpoints.len + 1);
            peer.?.endpoints[peer.?.endpoints.len - 1] = endpoint;
        }
        state_lock.unlock();
    }
}
