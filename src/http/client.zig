const std = @import("std");

/// Simple HTTP client for external API calls
pub const HttpClient = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) HttpClient {
        return HttpClient{
            .allocator = allocator,
        };
    }
    
    pub const HttpResponse = struct {
        status_code: u16,
        body: []u8,
        
        pub fn deinit(self: *HttpResponse, allocator: std.mem.Allocator) void {
            allocator.free(self.body);
        }
    };
    
    pub const HttpHeader = struct {
        name: []const u8,
        value: []const u8,
    };
    
    pub const RequestOptions = struct {
        headers: ?[]const HttpHeader = null,
        timeout_ms: u32 = 30000,
    };
    
    /// Make HTTP GET request
    pub fn get(self: *HttpClient, url: []const u8, options: RequestOptions) !HttpResponse {
        
        // Parse URL
        const uri = try std.Uri.parse(url);
        
        // Create HTTP client
        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();
        
        // Create request
        var req = try http_client.open(.GET, uri, .{
            .server_header_buffer = try self.allocator.alloc(u8, 8192),
        });
        defer {
            self.allocator.free(req.server_header_buffer);
            req.deinit();
        }
        
        // Add headers if provided
        if (options.headers) |headers| {
            for (headers) |header| {
                try req.headers.append(header.name, header.value);
            }
        }
        
        // Send request
        try req.send();
        try req.finish();
        try req.wait();
        
        // Read response
        const body = try req.readAll(self.allocator);
        
        return HttpResponse{
            .status_code = @intCast(req.response.status.phrase().len), // Simplified
            .body = body,
        };
    }
    
    /// Make HTTP POST request
    pub fn post(self: *HttpClient, url: []const u8, body: []const u8, options: RequestOptions) !HttpResponse {
        
        // Parse URL
        const uri = try std.Uri.parse(url);
        
        // Create HTTP client
        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();
        
        // Create request
        var req = try http_client.open(.POST, uri, .{
            .server_header_buffer = try self.allocator.alloc(u8, 8192),
        });
        defer {
            self.allocator.free(req.server_header_buffer);
            req.deinit();
        }
        
        // Add headers
        try req.headers.append("Content-Type", "application/json");
        if (options.headers) |headers| {
            for (headers) |header| {
                try req.headers.append(header.name, header.value);
            }
        }
        
        // Send request with body
        try req.send();
        try req.writeAll(body);
        try req.finish();
        try req.wait();
        
        // Read response
        const response_body = try req.readAll(self.allocator);
        
        return HttpResponse{
            .status_code = @intCast(req.response.status.phrase().len), // Simplified
            .body = response_body,
        };
    }
};

/// JSON RPC client for Ethereum calls
pub const JsonRpcClient = struct {
    http_client: HttpClient,
    endpoint: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) JsonRpcClient {
        return JsonRpcClient{
            .http_client = HttpClient.init(allocator),
            .endpoint = endpoint,
        };
    }
    
    pub const JsonRpcRequest = struct {
        jsonrpc: []const u8 = "2.0",
        id: u32,
        method: []const u8,
        params: std.json.Value,
    };
    
    pub const JsonRpcResponse = struct {
        jsonrpc: []const u8,
        id: u32,
        result: ?std.json.Value = null,
        @"error": ?std.json.Value = null,
    };
    
    /// Make JSON-RPC call
    pub fn call(self: *JsonRpcClient, request: JsonRpcRequest) !JsonRpcResponse {
        // Serialize request
        var arena = std.heap.ArenaAllocator.init(self.http_client.allocator);
        defer arena.deinit();
        
        const request_json = try std.json.stringifyAlloc(arena.allocator(), request, .{});
        
        // Make HTTP request
        const response = try self.http_client.post(self.endpoint, request_json, .{
            .headers = &[_]HttpClient.HttpHeader{
                .{ .name = "Content-Type", .value = "application/json" },
            },
        });
        defer response.body[0..].deinit(self.http_client.allocator);
        
        // Parse response
        const parsed = try std.json.parseFromSlice(JsonRpcResponse, arena.allocator(), response.body, .{});
        
        return parsed.value;
    }
    
    /// Call Ethereum contract function
    pub fn ethCall(self: *JsonRpcClient, to: []const u8, data: []const u8) ![]u8 {
        
        // Add to and data to first param
        var call_obj = std.json.ObjectMap.init(self.http_client.allocator);
        try call_obj.put("to", .{ .string = to });
        try call_obj.put("data", .{ .string = data });
        
        const request = JsonRpcRequest{
            .id = 1,
            .method = "eth_call",
            .params = .{ .array = std.json.Array.fromOwnedSlice(self.http_client.allocator, &[_]std.json.Value{
                .{ .object = call_obj },
                .{ .string = "latest" },
            }) },
        };
        
        const response = try self.call(request);
        
        if (response.result) |result| {
            if (result == .string) {
                return self.http_client.allocator.dupe(u8, result.string);
            }
        }
        
        return error.InvalidResponse;
    }
};