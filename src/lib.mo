import Types "HttpTypes";
import Itertools "mo:itertools/Iter";
import Sha256 "mo:sha2/Sha256";
import Text "mo:core/Text";
import Iter "mo:core/Iter";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Char "mo:core/Char";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Time "mo:core/Time";
import Int "mo:core/Int";
import BTree "mo:stableheapbtreemap/BTree";
import Map "mo:core/Map";
import Array "mo:core/Array";
import Runtime "mo:core/Runtime";
import xNum "mo:xtended-numbers/NatX";

module {
    public type HttpMethod = { #get; #post; #head };

    public type HttpHeaders = Map.Map<Text, [Text]>;

    public type HttpRequest = {
        method: HttpMethod;
        headers: HttpHeaders;
        url: Text;
        body: Blob;
    };

    func httpMethodToText(method: HttpMethod): Text {
        switch(method) {
            case(#get) { "GET" };
            case(#post) { "POST" };
            case(#head) { "HEAD" };
        };
    };

    public func serializeHttpRequest(request: HttpRequest): Blob {
        let method = httpMethodToText(request.method);
        let headers_list = Iter.map<(Text, [Text]), Text>(
            Map.entries(request.headers),
            func (entry: (Text, [Text])) { entry.0 # "\t" # Text.join("\t", entry.1.vals()); });
        let headers_joined = Itertools.reduce<Text>(headers_list, func(a: Text, b: Text) {a # "\r" # b});
        let headers_joined2 = switch (headers_joined) {
            case (?s) s;
            case null "";
        };
        let the_rest = Itertools.skip(request.url.chars(), 8); // strip "https://"
        let url = Text.fromIter(Itertools.skipWhile<Char>(the_rest, func (c: Char) { c != '/' }));
        let header_part = method # "\n" # url # "\n" # headers_joined2;

        let result = List.empty<Nat8>();
        List.addAll(result, Blob.toArray(Text.encodeUtf8(header_part)).vals());
        List.add(result, Nat8.fromNat(Nat32.toNat(Char.toNat32('\n'))));
        List.addAll(result, Blob.toArray(request.body).vals());
        Blob.fromArray(List.toArray(result));
    };

    public func hashOfHttpRequest(request: HttpRequest): Blob {
        // TODO: space inefficient
        let blob = serializeHttpRequest(request);
        Sha256.fromBlob(#sha256, blob);
    };

    public type HttpRequestsChecker = {
        hashes: BTree.BTree<Blob, Int>; // hash -> time
        times: BTree.BTree<Int, BTree.BTree<Blob, ()>>;
    };

    public func newHttpRequestsChecker(): HttpRequestsChecker {
        {
            hashes = BTree.init(null);
            times = BTree.init(null);
        }
    };

    private func deleteOldHttpRequests(checker: HttpRequestsChecker, params: {timeout: Nat}) {
        let threshold = Time.now() - params.timeout;
        label r loop {
            let ?(minTime, hashes) = BTree.min(checker.times) else {
                break r;
            };
            if (minTime > threshold) {
                break r;
            };
            for ((hash, _) in BTree.entries(hashes)) {
                ignore BTree.delete(checker.hashes, Blob.compare, hash);
            };
            ignore BTree.delete(checker.times, Int.compare, minTime);
        };
    };

    public func announceHttpRequestHash(checker: HttpRequestsChecker, hash: Blob, params: {timeout: Nat}) {
        deleteOldHttpRequests(checker, params);

        // If there is an old hash equal to this, first delete it to clean times:
        switch (BTree.get(checker.hashes, Blob.compare, hash)) {
            case (?oldTime) {
                let ?subtree = BTree.get(checker.times, Int.compare, oldTime) else {
                    Runtime.trap("programming error: zero times");
                };
                ignore BTree.delete(checker.hashes, Blob.compare, hash);
                if (BTree.size(subtree) == 1) {
                    ignore BTree.delete(checker.times, Int.compare, oldTime);
                } else {
                    ignore BTree.delete(subtree, Blob.compare, hash);
                };
            };
            case null {};
        };

        let now = Time.now();

        // Insert into two trees:
        ignore BTree.insert(checker.hashes, Blob.compare, hash, now);
        let subtree = switch (BTree.get(checker.times, Int.compare, now)) {
            case (?hashes) hashes;
            case (null) {
                let hashes = BTree.init<Blob, ()>(null);
                ignore BTree.insert(checker.times, Int.compare, now, hashes);
                hashes;
            }
        };
        ignore BTree.insert(subtree, Blob.compare, hash, ());
    };

    public func announceHttpRequest(checker: HttpRequestsChecker, request: HttpRequest, params: {timeout: Nat}) {
        announceHttpRequestHash(checker, hashOfHttpRequest(request), params);
    };

    public func checkHttpRequest(checker: HttpRequestsChecker, hash: Blob): Bool {
        BTree.has(checker.hashes, Blob.compare, hash);
    };

    func headersToLowercase(headers: HttpHeaders) {
        for (entry in Map.entries(headers)) {
            let lower = Text.toLower(entry.0);
            if (lower != entry.0) { // speed optimization
                ignore Map.delete<Text, [Text]>(headers, Text.compare, entry.0);
                ignore Map.insert(headers, Text.compare, lower, entry.1);
            }
        }
    };

    func modifyHttpRequest(request: HttpRequest) {
        let headers = request.headers;
        
        headersToLowercase(headers);

        // Some headers are added automatically, if missing. Provide them here, to match the hash:
        if (request.body != "") {
            ignore Map.insert(headers, Text.compare, "content-length", [xNum.toText(Array.size(Blob.toArray(request.body)))]); // TODO: https://github.com/dfinity/motoko-base/issues/637
        };
        if (not Map.containsKey(headers, Text.compare, "user-agent")) {
            ignore Map.insert(headers, Text.compare, "user-agent", ["IC/for-Join-Proxy"]);
        };
        if (not Map.containsKey(headers, Text.compare, "accept")) {
            ignore Map.insert(headers, Text.compare, "accept", ["*/*"]);
        };
        if (not Map.containsKey(headers, Text.compare, "host")) {
            let the_rest = Itertools.skip(request.url.chars(), 8); // strip "https://"
            // We don't worry if request.url really starts with "https://" because it will be caught later.
            let host = Itertools.takeWhile<Char>(the_rest, func (c: Char) { c != '/' });
            // As test_port_443 test shows, port is included in default Host: iff it is included in the URL.
            // So, we don't need add/remove :443 to match config on server.
            ignore Map.insert(headers, Text.compare, "host", [Text.fromIter(host)]);
        };
    };

    /// Note that `request` will be modified.
    public func checkedHttpRequest(
        checker: HttpRequestsChecker,
        request: HttpRequest,
        transform: ?Types.TransformRawResponseFunction,
        params: {cycles: Nat; timeout: Nat; max_response_bytes: ?Nat64},
    ): async* Types.HttpResponsePayload {
        modifyHttpRequest(request);
        announceHttpRequest(checker, request, params);
        let http_headers = List.empty<{name: Text; value: Text}>();
        for ((name, values) in Map.entries(request.headers)) { // ordered lexicographically
            for (value in values.vals()) {
                List.add(http_headers, {name; value});
            }
        };
        await (with cycles = params.cycles) Types.ic.http_request({
            method = request.method;
            headers = List.toArray(http_headers);
            url = request.url;
            body = ?Blob.toArray(request.body);
            transform = transform;
            max_response_bytes = params.max_response_bytes;
        });
    };

    public type WrappedHttpRequest = {
        method: HttpMethod;
        headers: Map.Map<Text, [Text]>;
        url: Text;
        body: Blob;
    };

    public type SharedWrappedHttpRequest = {
        method: HttpMethod;
        headers: [(Text, [Text])];
        url: Text;
        body: Blob;
    };

    public func checkedHttpRequestWrapped(
        checker: HttpRequestsChecker,
        request: SharedWrappedHttpRequest,
        transform: ?Types.TransformRawResponseFunction,
        params: {cycles: Nat; timeout: Nat; max_response_bytes: ?Nat64},
    ): async* Types.HttpResponsePayload {
        await* checkedHttpRequest(
            checker,
            {
                method = request.method;
                headers = Map.fromIter(request.headers.vals(), Text.compare);
                url = request.url;
                body = request.body;
            },
            transform,
            params,
        );
    };

    public func _headersNew(): Map.Map<Text, [Text]> {
        Map.empty<Text, [Text]>();
    };

    public func headersNew(): Map.Map<Text, [Text]> {
        Map.empty<Text, [Text]>();
    };
};